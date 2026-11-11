/**
 * @file test_secure.c
 * @brief Host test for authenticated frames: HMAC vectors, the handshake, and
 * every way a frame must be refused.
 *
 * The gateway's half is written here in C from the protocol in secure.h, so the
 * test checks the board against the protocol rather than against itself.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>

#include "robohub/secure.h"

static int failures = 0;
#define CHECK(cond, what) do { if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", what, __LINE__); failures++; } } while (0)

static rh_u32 fake_now = 1000u;
static rh_u32 clock_now(void) { return fake_now; }
static rh_u8 nonce_seed = 1u;
static int counting_nonce(rh_u8* out, rh_size n) { for (rh_size i = 0; i < n; i++) out[i] = (rh_u8)(nonce_seed + i); nonce_seed++; return 0; }
static int no_nonce(rh_u8* out, rh_size n) { (void)out; (void)n; return -1; }

static void hex(const char* text, rh_u8* out)
{
    for (size_t i = 0; text[2 * i]; i++) {
        unsigned v; sscanf(text + 2 * i, "%2x", &v); out[i] = (rh_u8)v;
    }
}

static void check_hmac_vectors(void)
{
    rh_u8 key[131], mac[32], want[32];
    memset(key, 0x0b, 20);
    robohub_secure_hmac(key, 20, (const rh_u8*)"Hi There", 8, mac, 32);
    hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want);
    CHECK(memcmp(mac, want, 32) == 0, "RFC 4231 case 1");
    robohub_secure_hmac((const rh_u8*)"Jefe", 4, (const rh_u8*)"what do ya want for nothing?", 28, mac, 32);
    hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", want);
    CHECK(memcmp(mac, want, 32) == 0, "RFC 4231 case 2");
    memset(key, 0xaa, 131);
    const char* m = "Test Using Larger Than Block-Size Key - Hash Key First";
    robohub_secure_hmac(key, 131, (const rh_u8*)m, (rh_size)strlen(m), mac, 32);
    hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", want);
    CHECK(memcmp(mac, want, 32) == 0, "RFC 4231 case 6 (key longer than a block)");
}

/* ---- the gateway's half, from the protocol ------------------------------ */

typedef struct { rh_u8 k_dev[16], k_up[16], k_down[16]; rh_u16 sid; rh_u32 up_ctr, down_ctr; } gateway_side;

static void hmac_parts(const rh_u8* key, rh_size kl, const rh_u8* const* parts, const rh_size* lens, int n, rh_u8* out, rh_size ol)
{
    rh_u8 buf[128]; rh_size used = 0;
    for (int i = 0; i < n; i++) { memcpy(buf + used, parts[i], lens[i]); used += lens[i]; }
    robohub_secure_hmac(key, kl, buf, used, out, ol);
}

static void derive_device_key(const rh_u8 k_gw[32], const rh_u8 uid[8], rh_u8 out[16])
{
    const rh_u8* parts[] = { (const rh_u8*)"rh-dev1", uid };
    rh_size lens[] = { 7, 8 };
    hmac_parts(k_gw, 32, parts, lens, 2, out, 16);
}

/* Answer a HELLO: check its tag, choose a session, derive both keys. */
static int gateway_answer(gateway_side* g, const rh_u8 hello[24], rh_u16 sid, rh_u16 lifetime, rh_u8 session[28])
{
    rh_u8 tag[8];
    const rh_u8* hp[] = { (const rh_u8*)"rh-hello1", hello };
    rh_size hl[] = { 9, 16 };
    hmac_parts(g->k_dev, 16, hp, hl, 2, tag, 8);
    if (memcmp(tag, hello + 16, 8) != 0) return -1;
    rh_u8 nonce_g[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    memcpy(session, hello, 8);
    session[8] = (rh_u8)sid; session[9] = (rh_u8)(sid >> 8);
    memcpy(session + 10, nonce_g, 8);
    session[18] = (rh_u8)lifetime; session[19] = (rh_u8)(lifetime >> 8);
    const rh_u8* sp[] = { (const rh_u8*)"rh-session1", hello, hello + 8, session + 8, nonce_g, session + 18 };
    rh_size sl[] = { 11, 8, 8, 2, 8, 2 };
    hmac_parts(g->k_dev, 16, sp, sl, 6, session + 20, 8);
    const rh_u8* up[] = { (const rh_u8*)"rh-up1", hello + 8, nonce_g };
    rh_size ul[] = { 6, 8, 8 };
    hmac_parts(g->k_dev, 16, up, ul, 3, g->k_up, 16);
    const rh_u8* dn[] = { (const rh_u8*)"rh-down1", hello + 8, nonce_g };
    rh_size dl[] = { 8, 8, 8 };
    hmac_parts(g->k_dev, 16, dn, dl, 3, g->k_down, 16);
    g->sid = sid; g->up_ctr = 0; g->down_ctr = 0;
    return 0;
}

/* Verify an upstream frame as the gateway would. */
static int gateway_open(gateway_side* g, rh_u16 msg_id, rh_u16 tx_id, const rh_u8* p, rh_size n)
{
    if ((msg_id & RH_SECURE_FLAG) == 0 || n < RH_SECURE_OVERHEAD) return -1;
    rh_u8 header[4] = { (rh_u8)msg_id, (rh_u8)(msg_id >> 8), (rh_u8)tx_id, (rh_u8)(tx_id >> 8) }, tag[8];
    const rh_u8* parts[] = { header, p, p + 6 };
    rh_size lens[] = { 4, 6, n - RH_SECURE_OVERHEAD };
    hmac_parts(g->k_up, 16, parts, lens, 3, tag, 8);
    rh_u32 ctr = (rh_u32)p[2] | ((rh_u32)p[3] << 8) | ((rh_u32)p[4] << 16) | ((rh_u32)p[5] << 24);
    if (memcmp(tag, p + n - 8, 8) != 0 || ctr <= g->up_ctr || (rh_u16)(p[0] | (p[1] << 8)) != g->sid) return -1;
    g->up_ctr = ctr;
    return 0;
}

/* Seal a downstream frame as the gateway would. */
static rh_size gateway_seal(gateway_side* g, rh_u16 msg_id, rh_u16 tx_id, const rh_u8* payload, rh_size n, rh_u8* out)
{
    g->down_ctr++;
    out[0] = (rh_u8)g->sid; out[1] = (rh_u8)(g->sid >> 8);
    for (int i = 0; i < 4; i++) out[2 + i] = (rh_u8)(g->down_ctr >> (8 * i));
    memcpy(out + 6, payload, n);
    rh_u16 flagged = (rh_u16)(msg_id | RH_SECURE_FLAG);
    rh_u8 header[4] = { (rh_u8)flagged, (rh_u8)(flagged >> 8), (rh_u8)tx_id, (rh_u8)(tx_id >> 8) };
    const rh_u8* parts[] = { header, out, out + 6 };
    rh_size lens[] = { 4, 6, n };
    hmac_parts(g->k_down, 16, parts, lens, 3, out + 6 + n, 8);
    return n + RH_SECURE_OVERHEAD;
}

int main(void)
{
    check_hmac_vectors();

    rh_u8 k_gw[32]; for (int i = 0; i < 32; i++) k_gw[i] = (rh_u8)(0x40 + i);
    rh_u8 uid[8] = { 0xE6, 0x61, 0x41, 0x04, 0x03, 0x62, 0x6A, 0x2B };
    gateway_side g;
    derive_device_key(k_gw, uid, g.k_dev);

    RoboHubSecure board;
    CHECK(robohub_secure_init(&board, uid, g.k_dev, counting_nonce, clock_now) == ROBOHUB_OK, "init");
    CHECK(!robohub_secure_ready(&board), "no session before the handshake");
    rh_u8 out[64]; rh_size out_len = 0;
    CHECK(robohub_secure_seal(&board, 0x0204, 1, (const rh_u8*)"x", 1, out, sizeof(out), &out_len) == ROBOHUB_ERR_STATE,
          "nothing is sealed before a session");

    rh_u8 hello[RH_SECURE_HELLO_SIZE], session[RH_SECURE_SESSION_SIZE];
    CHECK(robohub_secure_hello(&board, hello) == ROBOHUB_OK, "hello");
    rh_u8 old_hello[RH_SECURE_HELLO_SIZE]; memcpy(old_hello, hello, sizeof(hello));
    CHECK(gateway_answer(&g, hello, 0x1234, 3600, session) == 0, "the gateway accepts the hello");

    /* A tampered session is refused, and does not end the wait for a good one. */
    rh_u8 bad[RH_SECURE_SESSION_SIZE]; memcpy(bad, session, sizeof(bad)); bad[18] ^= 1;
    CHECK(robohub_secure_accept(&board, bad, sizeof(bad)) != ROBOHUB_OK, "a session with a changed lifetime");
    CHECK(robohub_secure_accept(&board, session, sizeof(session)) == ROBOHUB_OK, "the session");
    CHECK(robohub_secure_ready(&board), "ready after the handshake");

    /* Up: the gateway accepts a sealed reading once, and only once. */
    const rh_u8 reading[] = { 1, 7, 0, 0, 0x2A };
    CHECK(robohub_secure_seal(&board, 0x0204, 5, reading, sizeof(reading), out, sizeof(out), &out_len) == ROBOHUB_OK, "seal");
    CHECK(out_len == sizeof(reading) + RH_SECURE_OVERHEAD, "sealed length");
    CHECK(gateway_open(&g, 0x0204 | RH_SECURE_FLAG, 5, out, out_len) == 0, "the gateway opens it");
    CHECK(gateway_open(&g, 0x0204 | RH_SECURE_FLAG, 5, out, out_len) != 0, "a replayed frame");
    CHECK(robohub_secure_seal(&board, 0x0204, 6, reading, sizeof(reading), out, sizeof(out), &out_len) == ROBOHUB_OK, "seal 2");
    out[7] ^= 0x01;
    CHECK(gateway_open(&g, 0x0204 | RH_SECURE_FLAG, 6, out, out_len) != 0, "a changed payload byte");
    CHECK(robohub_secure_seal(&board, 0x0204, 7, reading, sizeof(reading), out, sizeof(out), &out_len) == ROBOHUB_OK, "seal 3");
    CHECK(gateway_open(&g, 0x0205 | RH_SECURE_FLAG, 7, out, out_len) != 0, "a changed message id");

    /* Down: the board accepts a command once, refuses a replay, a change, and a
     * frame without the flag. */
    const rh_u8 command[] = { 1, 0, 0x10, 0x27 };
    rh_u8 frame[64];
    rh_size n = gateway_seal(&g, 0x0301, 9, command, sizeof(command), frame);
    const rh_u8* inner = 0; rh_size inner_len = 0;
    CHECK(robohub_secure_open(&board, 0x0301 | RH_SECURE_FLAG, 9, frame, n, &inner, &inner_len) == ROBOHUB_OK, "open a command");
    CHECK(inner_len == sizeof(command) && memcmp(inner, command, sizeof(command)) == 0, "the command's bytes");
    CHECK(robohub_secure_open(&board, 0x0301 | RH_SECURE_FLAG, 9, frame, n, &inner, &inner_len) != ROBOHUB_OK, "a replayed command");
    n = gateway_seal(&g, 0x0301, 10, command, sizeof(command), frame);
    CHECK(robohub_secure_open(&board, 0x0301, 10, frame, n, &inner, &inner_len) != ROBOHUB_OK, "a frame without the flag");
    frame[n - 1] ^= 0x80;
    CHECK(robohub_secure_open(&board, 0x0301 | RH_SECURE_FLAG, 10, frame, n, &inner, &inner_len) != ROBOHUB_OK, "a changed tag");

    /* A session answering an earlier hello is not accepted after a new one. */
    CHECK(robohub_secure_hello(&board, hello) == ROBOHUB_OK, "a new hello");
    rh_u8 stale[RH_SECURE_SESSION_SIZE];
    gateway_side g_old = g;
    CHECK(gateway_answer(&g_old, old_hello, 0x0001, 3600, stale) == 0, "an answer to the old hello");
    CHECK(robohub_secure_accept(&board, stale, sizeof(stale)) != ROBOHUB_OK, "a replayed session for an old hello");

    /* Expiry ends the session. */
    CHECK(gateway_answer(&g, hello, 0x2222, 2, session) == 0, "a short session");
    CHECK(robohub_secure_accept(&board, session, sizeof(session)) == ROBOHUB_OK, "accept the short session");
    fake_now += 2500u;
    CHECK(!robohub_secure_ready(&board), "an expired session");
    CHECK(robohub_secure_seal(&board, 0x0204, 11, reading, sizeof(reading), out, sizeof(out), &out_len) == ROBOHUB_ERR_STATE,
          "nothing is sealed after expiry");

    /* A different board's key does not open this board's session. */
    rh_u8 other_uid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, other_key[16];
    derive_device_key(k_gw, other_uid, other_key);
    CHECK(memcmp(other_key, g.k_dev, 16) != 0, "device keys differ per board");

    /* No nonce source, no session. */
    RoboHubSecure none;
    robohub_secure_init(&none, uid, g.k_dev, no_nonce, clock_now);
    CHECK(robohub_secure_hello(&none, hello) == ROBOHUB_ERR_NOT_SUPPORTED, "no hello without a nonce source");

    if (failures == 0) {
        printf("test_secure: all checks passed\n");
    }
    return failures == 0 ? 0 : 1;
}
