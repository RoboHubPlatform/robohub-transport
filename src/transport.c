/*
 * transport.c — COBS framing, a Fletcher-16 check, and a byte-at-a-time parser.
 *
 * The parser is a few states worth of work per byte and no allocation: bytes
 * land in the instance's receive buffer, a complete frame is decoded onto the
 * stack, and a frame that checks out is published on the event bus before
 * `feed_byte` returns. Nothing here blocks, so it is safe to call from the
 * interrupt that delivered the byte.
 *
 * @project RoboHub Platform
 * @license MIT
 */

#include "robohub/transport.h"
#include "robohub/core/event.h"

#include <string.h>

/* A COBS frame adds one length byte per 254 payload bytes and one for the run
 * still open at the end, so an encoded frame is at most this wide. */
#define RH_TRANSPORT_ENCODED_MAX \
    (RH_TRANSPORT_MAX_FRAME_SIZE + (RH_TRANSPORT_MAX_FRAME_SIZE / 254u) + 1u)

/* -------------------------------------------------------------------------- */
/*  Integrity                                                                 */
/* -------------------------------------------------------------------------- */

/*
 * Fletcher-16: two running sums modulo 255, concatenated. It costs an add and a
 * compare per byte and catches the errors a serial line actually makes — a
 * flipped bit, a dropped byte, a transposition — where a table-driven CRC would
 * cost a table this library would have to carry.
 */
static rh_u16 fletcher16(const rh_u8* data, rh_size length)
{
    rh_u16 sum1 = 0u;
    rh_u16 sum2 = 0u;
    for (rh_size i = 0; i < length; i++) {
        sum1 = (rh_u16)((sum1 + data[i]) % 255u);
        sum2 = (rh_u16)((sum2 + sum1) % 255u);
    }
    return (rh_u16)((sum2 << 8) | sum1);
}

/* -------------------------------------------------------------------------- */
/*  COBS                                                                      */
/* -------------------------------------------------------------------------- */

/* Encode into `output`, which must hold RH_TRANSPORT_ENCODED_MAX bytes. Returns
 * the encoded length; the caller appends the delimiter. */
static rh_size cobs_encode(const rh_u8* input, rh_size length, rh_u8* output)
{
    rh_size read_index = 0u;
    rh_size write_index = 1u;
    rh_size code_index = 0u;
    rh_u8 code = 1u;

    while (read_index < length) {
        if (input[read_index] == 0u) {
            output[code_index] = code;
            code = 1u;
            code_index = write_index++;
            read_index++;
        } else {
            output[write_index++] = input[read_index++];
            code++;
            if (code == 0xFFu) {
                output[code_index] = code;
                code = 1u;
                code_index = write_index++;
            }
        }
    }
    output[code_index] = code;
    return write_index;
}

/* Decode into `output`, which must hold at least `length` bytes. Returns the
 * decoded length, or 0 when the input is truncated or malformed. */
static rh_size cobs_decode(const rh_u8* input, rh_size length, rh_u8* output, rh_size capacity)
{
    rh_size read_index = 0u;
    rh_size write_index = 0u;

    while (read_index < length) {
        rh_u8 code = input[read_index++];
        if (code == 0u) {
            return 0u; /* a zero code has no meaning inside a COBS frame */
        }
        for (rh_u8 i = 1u; i < code; i++) {
            if (read_index >= length || write_index >= capacity) {
                return 0u;
            }
            output[write_index++] = input[read_index++];
        }
        /* A code short of 0xFF stands for the zero it replaced, unless it is the
         * final code. */
        if (code < 0xFFu && read_index < length) {
            if (write_index >= capacity) {
                return 0u;
            }
            output[write_index++] = 0x00u;
        }
    }
    return write_index;
}

/* -------------------------------------------------------------------------- */
/*  Little-endian helpers                                                     */
/* -------------------------------------------------------------------------- */

static void put_u16(rh_u8* out, rh_u16 value)
{
    out[0] = (rh_u8)(value & 0xFFu);
    out[1] = (rh_u8)((value >> 8) & 0xFFu);
}

static rh_u16 get_u16(const rh_u8* in)
{
    return (rh_u16)((rh_u16)in[0] | ((rh_u16)in[1] << 8));
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

RoboHubError robohub_transport_init(RoboHubTransport* transport,
                                    const RoboHubTransportPhy* phy)
{
    if (transport == 0 || phy == 0 || phy->write == 0) {
        return ROBOHUB_ERR_INVALID_ARG;
    }
    memset(transport, 0, sizeof(*transport));
    transport->phy = *phy;
    return ROBOHUB_OK;
}

/* A frame that just finished is decoded, checked and, if it passes, published.
 * Anything wrong with it is counted and dropped: a stream has no way to ask for
 * the bytes again, and a half-frame is not worth keeping. */
static void transport_deliver(RoboHubTransport* transport)
{
    rh_u8 frame[RH_TRANSPORT_MAX_FRAME_SIZE];
    rh_size decoded = cobs_decode(transport->rx, transport->rx_length, frame, sizeof(frame));

    if (decoded < RH_TRANSPORT_MIN_FRAME) {
        transport->dropped++;
        return;
    }

    rh_u16 msg_id = get_u16(&frame[0]);
    rh_u16 tx_id = get_u16(&frame[2]);
    rh_u16 payload_len = get_u16(&frame[4]);

    if ((rh_size)RH_TRANSPORT_HEADER_SIZE + payload_len + RH_TRANSPORT_CRC_SIZE != decoded) {
        transport->dropped++;
        return;
    }

    rh_u16 expected = get_u16(&frame[RH_TRANSPORT_HEADER_SIZE + payload_len]);
    rh_u16 actual = fletcher16(frame, (rh_size)RH_TRANSPORT_HEADER_SIZE + payload_len);

    if (expected != actual) {
        transport->crc_errors++;
        return;
    }

    transport->rx_packets++;
    (void)robohub_core_event_publish_with_tx((robohub_event_id)msg_id, tx_id,
                                             &frame[RH_TRANSPORT_HEADER_SIZE], payload_len);
}

void robohub_transport_feed_byte(RoboHubTransport* transport, rh_u8 byte)
{
    if (byte == RH_TRANSPORT_DELIMITER) {
        if (transport->rx_length > 0u) {
            transport_deliver(transport);
            transport->rx_length = 0u;
        }
        return;
    }

    if (transport->rx_length < RH_TRANSPORT_MAX_FRAME_SIZE) {
        transport->rx[transport->rx_length++] = byte;
    } else {
        /* The frame is longer than any frame can be, so there is no point
         * keeping the rest of it: drop what is held and let the next delimiter
         * start clean. */
        transport->dropped++;
        transport->rx_length = 0u;
    }
}

void robohub_transport_feed(RoboHubTransport* transport, const rh_u8* data, rh_size length)
{
    if (transport == 0 || data == 0) {
        return;
    }
    for (rh_size i = 0; i < length; i++) {
        robohub_transport_feed_byte(transport, data[i]);
    }
}

RoboHubError robohub_transport_send(RoboHubTransport* transport,
                                    robohub_event_id msg_id,
                                    rh_u16 tx_id,
                                    const void* payload,
                                    rh_u16 payload_len)
{
    if (transport == 0 || transport->phy.write == 0) {
        return ROBOHUB_ERR_STATE;
    }
    if ((rh_size)RH_TRANSPORT_HEADER_SIZE + payload_len + RH_TRANSPORT_CRC_SIZE
        > RH_TRANSPORT_MAX_FRAME_SIZE) {
        return ROBOHUB_ERR_INVALID_ARG;
    }

    rh_u8 frame[RH_TRANSPORT_MAX_FRAME_SIZE];
    put_u16(&frame[0], (rh_u16)msg_id);
    put_u16(&frame[2], tx_id);
    put_u16(&frame[4], payload_len);
    if (payload_len > 0u && payload != 0) {
        memcpy(&frame[RH_TRANSPORT_HEADER_SIZE], payload, payload_len);
    }
    rh_size body = (rh_size)RH_TRANSPORT_HEADER_SIZE + payload_len;
    put_u16(&frame[body], fletcher16(frame, body));
    body += RH_TRANSPORT_CRC_SIZE;

    rh_u8 encoded[RH_TRANSPORT_ENCODED_MAX + 1u];
    rh_size encoded_len = cobs_encode(frame, body, encoded);
    encoded[encoded_len++] = RH_TRANSPORT_DELIMITER;

    if (transport->phy.write(encoded, encoded_len, transport->phy.context) != 0) {
        return ROBOHUB_ERR_IO;
    }
    transport->tx_packets++;
    return ROBOHUB_OK;
}
