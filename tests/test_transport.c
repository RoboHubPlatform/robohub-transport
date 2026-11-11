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


/* ---- an authenticated link ----------------------------------------------- */

static rh_u8 hello_seen[RH_SECURE_HELLO_SIZE];
static int hellos;
static RoboHubError on_hello(robohub_event_id id, const void* payload, rh_size size, void* user)
{
    (void)id; (void)user;
    if (size == RH_SECURE_HELLO_SIZE) {
        memcpy(hello_seen, payload, size);
        hellos++;
    }
    return ROBOHUB_OK;
}

static int flagged;
static RoboHubError on_flagged(robohub_event_id id, const void* payload, rh_size size, void* user)
{
    (void)id; (void)payload; (void)size; (void)user;
    flagged++;
    return ROBOHUB_OK;
}

static rh_u32 now_ms_value = 5000u;
static rh_u32 test_now(void) { return now_ms_value; }
static int test_nonce(rh_u8* out, rh_size n) { for (rh_size i = 0; i < n; i++) out[i] = (rh_u8)(0x30u + i); return 0; }

/* The gateway's answer to a hello, from the protocol in secure.h. */
static void answer_hello(const rh_u8 k_dev[16], const rh_u8 hello[RH_SECURE_HELLO_SIZE], rh_u8 session[RH_SECURE_SESSION_SIZE])
{
    const rh_u8 nonce_g[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    memcpy(session, hello, 8);
    session[8] = 0x34u; session[9] = 0x12u;
    memcpy(session + 10, nonce_g, 8);
    session[18] = 0x10u; session[19] = 0x0Eu; /* 3600 s */
    rh_u8 material[11 + 8 + 8 + 2 + 8 + 2];
    memcpy(material, "rh-session1", 11);
    memcpy(material + 11, hello, 16);
    memcpy(material + 27, session + 8, 2);
    memcpy(material + 29, nonce_g, 8);
    memcpy(material + 37, session + 18, 2);
    robohub_secure_hmac(k_dev, 16, material, sizeof(material), session + 20, 8);
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

    /* An authenticated link sends nothing unauthenticated: the first send says
     * hello instead, a reading follows only once the session is up, it leaves
     * flagged, and a plain frame arriving is dropped. */
    assert(robohub_core_event_subscribe((robohub_event_id)RH_SECURE_MSG_HELLO, on_hello, 0) == ROBOHUB_OK);
    assert(robohub_core_event_subscribe((robohub_event_id)(TEST_EVENT | RH_SECURE_FLAG), on_flagged, 0) == ROBOHUB_OK);
    RoboHubTransport gateway_end;
    RoboHubTransport board;
    const RoboHubTransportPhy to_gateway = { .write = forward_write, .context = &gateway_end };
    const RoboHubTransportPhy to_board = { .write = forward_write, .context = &board };
    assert(robohub_transport_init(&gateway_end, &to_board) == ROBOHUB_OK);
    assert(robohub_transport_init(&board, &to_gateway) == ROBOHUB_OK);
    const rh_u8 uid[8] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 };
    const rh_u8 k_dev[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0F };
    RoboHubSecure secure;
    assert(robohub_secure_init(&secure, uid, k_dev, test_nonce, test_now) == ROBOHUB_OK);
    assert(robohub_transport_secure(&board, &secure) == ROBOHUB_OK);

    int delivered = deliveries;
    assert(robohub_transport_send(&board, TEST_EVENT, 1u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_ERR_STATE);
    assert(hellos == 1);
    assert(deliveries == delivered); /* the reading itself was not sent */
    assert(robohub_transport_send(&board, TEST_EVENT, 2u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_ERR_STATE);
    assert(hellos == 1); /* an unanswered hello is not repeated at once */
    now_ms_value += 2500u;
    assert(robohub_transport_send(&board, TEST_EVENT, 3u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_ERR_STATE);
    assert(hellos == 2); /* but is, two seconds later */

    rh_u8 session[RH_SECURE_SESSION_SIZE];
    answer_hello(k_dev, hello_seen, session);
    assert(robohub_transport_send(&gateway_end, (robohub_event_id)RH_SECURE_MSG_SESSION, 0u, session, (rh_u16)sizeof(session)) == ROBOHUB_OK);
    assert(robohub_secure_ready(&secure));

    assert(robohub_transport_send(&board, TEST_EVENT, 4u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_OK);
    assert(flagged == 1);              /* it arrived, flagged, at the gateway's end */
    assert(deliveries == delivered);   /* and was never delivered as a plain frame */

    rh_u32 dropped = board.dropped;
    assert(robohub_transport_send(&gateway_end, TEST_EVENT, 5u, payload, (rh_u16)sizeof(payload)) == ROBOHUB_OK);
    assert(deliveries == delivered);   /* a plain frame to an authenticated board is dropped */
    assert(board.dropped == dropped + 1u);

    return 0;
}
