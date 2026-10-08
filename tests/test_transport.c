/*
 * test_transport.c — framing round-trips, COBS escaping, and a corrupt frame.
 *
 * @project RoboHub Platform
 * @license MIT
 */

#include "robohub/transport.h"
#include "robohub/core/event.h"
#include "core_internal.h" /* the event bus initialiser, for a test with no runtime */

#include <assert.h>
#include <string.h>

#define TEST_EVENT ((robohub_event_id)0x1234u)

static int deliveries;
static robohub_event_id seen_id;
static rh_u16 seen_tx;
static rh_size seen_len;
static rh_u8 seen[32];

static RoboHubError on_event(robohub_event_id id, const void* payload, rh_size size, void* user)
{
    (void)user;
    deliveries++;
    seen_id = id;
    seen_tx = robohub_core_event_current_tx();
    seen_len = size;
    if (size <= sizeof(seen)) {
        memcpy(seen, payload, size);
    }
    return ROBOHUB_OK;
}

/* A link that is really the other end: what is written lands in `sink`. */
static int forward_write(const rh_u8* data, rh_size length, void* context)
{
    robohub_transport_feed((RoboHubTransport*)context, data, length);
    return 0;
}

/* A link that keeps what it was given, so a frame can be inspected and damaged. */
static rh_u8 captured[RH_TRANSPORT_MAX_FRAME_SIZE + 4u];
static rh_size captured_len;

static int capture_write(const rh_u8* data, rh_size length, void* context)
{
    (void)context;
    assert(length <= sizeof(captured));
    memcpy(captured, data, length);
    captured_len = length;
    return 0;
}

int main(void)
{
    assert(robohub_core_event_init() == ROBOHUB_OK);
    assert(robohub_core_event_subscribe(TEST_EVENT, on_event, 0) == ROBOHUB_OK);

    /* A payload full of zeros and an 0xFF: the bytes COBS exists to hide. */
    const rh_u8 payload[] = { 0x01, 0x00, 0x02, 0x00, 0xFF, 0x00 };
    RoboHubTransport receiver;
    RoboHubTransport sender;
    const RoboHubTransportPhy link = { .write = forward_write, .context = &receiver };

    assert(robohub_transport_init(&receiver, &link) == ROBOHUB_OK);
    assert(robohub_transport_init(&sender, &link) == ROBOHUB_OK);

    assert(robohub_transport_send(&sender, TEST_EVENT, 42u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_OK);
    assert(deliveries == 1);
    assert(seen_id == TEST_EVENT);
    assert(seen_tx == 42u);
    assert(seen_len == sizeof(payload));
    assert(memcmp(seen, payload, sizeof(payload)) == 0);
    assert(sender.tx_packets == 1u);
    assert(receiver.rx_packets == 1u);
    assert(receiver.crc_errors == 0u);

    /* The delimiter appears only at the end: that is what lets the parser find a
     * boundary without a timer. */
    RoboHubTransport capturer;
    const RoboHubTransportPhy capture = { .write = capture_write, .context = 0 };
    assert(robohub_transport_init(&capturer, &capture) == ROBOHUB_OK);
    assert(robohub_transport_send(&capturer, TEST_EVENT, 7u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_OK);
    assert(captured_len > 0u);
    assert(captured[captured_len - 1u] == RH_TRANSPORT_DELIMITER);
    for (rh_size i = 0; i + 1u < captured_len; i++) {
        assert(captured[i] != RH_TRANSPORT_DELIMITER);
    }

    /* A byte changed in flight is caught, counted, and not delivered. */
    int before = deliveries;
    captured[2] ^= 0x40u;
    robohub_transport_feed(&receiver, captured, captured_len);
    assert(deliveries == before);
    assert(receiver.crc_errors == 1u);

    /* Noise longer than a frame is dropped rather than kept. */
    rh_u8 noise[RH_TRANSPORT_MAX_FRAME_SIZE + 8u];
    memset(noise, 0x5Au, sizeof(noise));
    robohub_transport_feed(&receiver, noise, sizeof(noise));
    assert(receiver.dropped >= 1u);

    return 0;
}
