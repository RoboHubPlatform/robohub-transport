/**
 * @file secure.c
 * @brief Authenticated frames: the session handshake, sealing and opening.
 *
 * See secure.h for the protocol. SHA-256 (FIPS 180-4) and HMAC (RFC 2104) are
 * written out here with no allocation, so the same code runs on an 8-bit part
 * and on a host test.
 *
 * @project RoboHub Platform
 * SPDX-License-Identifier: MIT
 */

#include "robohub/secure.h"

#include <string.h>

/* -------------------------------------------------------------------------- */
/*  SHA-256                                                                   */
/* -------------------------------------------------------------------------- */

typedef struct {
    rh_u32 state[8];
    rh_u32 bits_low;
    rh_u32 bits_high;
    rh_u8 block[64];
    rh_size used;
} rh_sha256;

static const rh_u32 rh_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define RH_ROTR(x, n) (((x) >> (n)) | ((x) << (32u - (n))))

static void rh_sha256_compress(rh_sha256* c, const rh_u8* p)
{
    rh_u32 w[64];
    for (rh_u32 i = 0; i < 16u; i++) {
        w[i] = ((rh_u32)p[4u * i] << 24) | ((rh_u32)p[4u * i + 1u] << 16) |
               ((rh_u32)p[4u * i + 2u] << 8) | (rh_u32)p[4u * i + 3u];
    }
    for (rh_u32 i = 16u; i < 64u; i++) {
        rh_u32 s0 = RH_ROTR(w[i - 15u], 7u) ^ RH_ROTR(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
        rh_u32 s1 = RH_ROTR(w[i - 2u], 17u) ^ RH_ROTR(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    rh_u32 a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    rh_u32 e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
    for (rh_u32 i = 0; i < 64u; i++) {
        rh_u32 t1 = h + (RH_ROTR(e, 6u) ^ RH_ROTR(e, 11u) ^ RH_ROTR(e, 25u)) + ((e & f) ^ (~e & g)) + rh_sha256_k[i] + w[i];
        rh_u32 t2 = (RH_ROTR(a, 2u) ^ RH_ROTR(a, 13u) ^ RH_ROTR(a, 22u)) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void rh_sha256_init(rh_sha256* c)
{
    static const rh_u32 iv[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    memcpy(c->state, iv, sizeof(iv));
    c->bits_low = 0u;
    c->bits_high = 0u;
    c->used = 0u;
}

static void rh_sha256_update(rh_sha256* c, const rh_u8* data, rh_size n)
{
    for (rh_size i = 0; i < n; i++) {
        c->block[c->used++] = data[i];
        c->bits_low += 8u;
        if (c->bits_low < 8u) {
            c->bits_high++;
        }
        if (c->used == 64u) {
            rh_sha256_compress(c, c->block);
            c->used = 0u;
        }
    }
}

static void rh_sha256_final(rh_sha256* c, rh_u8 out[32])
{
    rh_u32 low = c->bits_low, high = c->bits_high;
    c->block[c->used++] = 0x80u;
    if (c->used > 56u) {
        while (c->used < 64u) {
            c->block[c->used++] = 0u;
        }
        rh_sha256_compress(c, c->block);
        c->used = 0u;
    }
    while (c->used < 56u) {
        c->block[c->used++] = 0u;
    }
    for (rh_u32 i = 0; i < 4u; i++) {
        c->block[56u + i] = (rh_u8)(high >> (24u - 8u * i));
        c->block[60u + i] = (rh_u8)(low >> (24u - 8u * i));
    }
    rh_sha256_compress(c, c->block);
    for (rh_u32 i = 0; i < 8u; i++) {
        out[4u * i] = (rh_u8)(c->state[i] >> 24);
        out[4u * i + 1u] = (rh_u8)(c->state[i] >> 16);
        out[4u * i + 2u] = (rh_u8)(c->state[i] >> 8);
        out[4u * i + 3u] = (rh_u8)c->state[i];
    }
}

/* -------------------------------------------------------------------------- */
/*  HMAC-SHA256                                                               */
/* -------------------------------------------------------------------------- */

typedef struct {
    rh_sha256 inner;
    rh_u8 outer_pad[64];
} rh_hmac;

static void rh_hmac_begin(rh_hmac* h, const rh_u8* key, rh_size key_length)
{
    rh_u8 block[64];
    memset(block, 0, sizeof(block));
    if (key_length > 64u) {
        rh_sha256 c;
        rh_sha256_init(&c);
        rh_sha256_update(&c, key, key_length);
        rh_sha256_final(&c, block);
    } else {
        memcpy(block, key, key_length);
    }
    rh_u8 inner_pad[64];
    for (rh_u32 i = 0; i < 64u; i++) {
        inner_pad[i] = (rh_u8)(block[i] ^ 0x36u);
        h->outer_pad[i] = (rh_u8)(block[i] ^ 0x5cu);
    }
    rh_sha256_init(&h->inner);
    rh_sha256_update(&h->inner, inner_pad, 64u);
}

static void rh_hmac_add(rh_hmac* h, const rh_u8* data, rh_size n)
{
    rh_sha256_update(&h->inner, data, n);
}

static void rh_hmac_end(rh_hmac* h, rh_u8* out, rh_size out_length)
{
    rh_u8 inner[32], mac[32];
    rh_sha256_final(&h->inner, inner);
    rh_sha256 outer;
    rh_sha256_init(&outer);
    rh_sha256_update(&outer, h->outer_pad, 64u);
    rh_sha256_update(&outer, inner, 32u);
    rh_sha256_final(&outer, mac);
    if (out_length > 32u) {
        out_length = 32u;
    }
    memcpy(out, mac, out_length);
}

void robohub_secure_hmac(const rh_u8* key, rh_size key_length,
                         const rh_u8* message, rh_size message_length,
                         rh_u8* out, rh_size out_length)
{
    rh_hmac h;
    rh_hmac_begin(&h, key, key_length);
    rh_hmac_add(&h, message, message_length);
    rh_hmac_end(&h, out, out_length);
}

/* A tag comparison that takes as long whether the first byte differs or the last. */
static int rh_equal(const rh_u8* a, const rh_u8* b, rh_size n)
{
    rh_u8 diff = 0u;
    for (rh_size i = 0; i < n; i++) {
        diff |= (rh_u8)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

static const rh_u8 RH_LABEL_HELLO[] = "rh-hello1";
static const rh_u8 RH_LABEL_SESSION[] = "rh-session1";
static const rh_u8 RH_LABEL_UP[] = "rh-up1";
static const rh_u8 RH_LABEL_DOWN[] = "rh-down1";

static void rh_put_u16(rh_u8* out, rh_u16 v) { out[0] = (rh_u8)v; out[1] = (rh_u8)(v >> 8); }
static void rh_put_u32(rh_u8* out, rh_u32 v) { out[0] = (rh_u8)v; out[1] = (rh_u8)(v >> 8); out[2] = (rh_u8)(v >> 16); out[3] = (rh_u8)(v >> 24); }
static rh_u16 rh_get_u16(const rh_u8* in) { return (rh_u16)(in[0] | ((rh_u16)in[1] << 8)); }
static rh_u32 rh_get_u32(const rh_u8* in) { return (rh_u32)in[0] | ((rh_u32)in[1] << 8) | ((rh_u32)in[2] << 16) | ((rh_u32)in[3] << 24); }

/* -------------------------------------------------------------------------- */
/*  The platform's nonce source                                               */
/* -------------------------------------------------------------------------- */

/* With no source, no session: a nonce that fell back to something predictable
 * would let an old SESSION be replayed. A platform overrides this. */
__attribute__((weak)) int robohub_platform_nonce(rh_u8* out, rh_size length)
{
    (void)out;
    (void)length;
    return -1;
}

/* -------------------------------------------------------------------------- */
/*  Session                                                                   */
/* -------------------------------------------------------------------------- */

RoboHubError robohub_secure_init(RoboHubSecure* secure,
                                 const rh_u8 uid[RH_SECURE_UID_SIZE],
                                 const rh_u8 device_key[RH_SECURE_KEY_SIZE],
                                 RoboHubSecureNonce nonce,
                                 RoboHubSecureClock now_ms)
{
    if (secure == 0 || uid == 0 || device_key == 0 || now_ms == 0) {
        return ROBOHUB_ERR_INVALID_ARG;
    }
    memset(secure, 0, sizeof(*secure));
    memcpy(secure->uid, uid, RH_SECURE_UID_SIZE);
    memcpy(secure->device_key, device_key, RH_SECURE_KEY_SIZE);
    secure->nonce = nonce != 0 ? nonce : robohub_platform_nonce;
    secure->now_ms = now_ms;
    return ROBOHUB_OK;
}

int robohub_secure_ready(const RoboHubSecure* secure)
{
    if (secure == 0 || secure->state != RH_SECURE_ESTABLISHED) {
        return 0;
    }
    /* Compared as a signed difference, so the clock wrapping after 49 days does
     * not end every session at once. */
    return (rh_i32)(secure->expires_ms - secure->now_ms()) > 0 &&
           secure->tx_counter < 0xFFFFFFF0u;
}

RoboHubError robohub_secure_hello(RoboHubSecure* secure, rh_u8 out[RH_SECURE_HELLO_SIZE])
{
    if (secure == 0 || out == 0) {
        return ROBOHUB_ERR_INVALID_ARG;
    }
    if (secure->nonce(secure->nonce_b, RH_SECURE_NONCE_SIZE) != 0) {
        return ROBOHUB_ERR_NOT_SUPPORTED;
    }
    memcpy(out, secure->uid, RH_SECURE_UID_SIZE);
    memcpy(out + RH_SECURE_UID_SIZE, secure->nonce_b, RH_SECURE_NONCE_SIZE);
    rh_hmac h;
    rh_hmac_begin(&h, secure->device_key, RH_SECURE_KEY_SIZE);
    rh_hmac_add(&h, RH_LABEL_HELLO, sizeof(RH_LABEL_HELLO) - 1u);
    rh_hmac_add(&h, out, RH_SECURE_UID_SIZE + RH_SECURE_NONCE_SIZE);
    rh_hmac_end(&h, out + RH_SECURE_UID_SIZE + RH_SECURE_NONCE_SIZE, RH_SECURE_TAG_SIZE);
    secure->state = RH_SECURE_HELLO_SENT;
    return ROBOHUB_OK;
}

RoboHubError robohub_secure_accept(RoboHubSecure* secure, const rh_u8* payload, rh_size length)
{
    if (secure == 0 || payload == 0 || length != RH_SECURE_SESSION_SIZE ||
        secure->state != RH_SECURE_HELLO_SENT ||
        memcmp(payload, secure->uid, RH_SECURE_UID_SIZE) != 0) {
        if (secure != 0) {
            secure->rejected++;
        }
        return ROBOHUB_ERR_PROTOCOL;
    }
    const rh_u8* sid = payload + RH_SECURE_UID_SIZE;
    const rh_u8* nonce_g = sid + 2u;
    const rh_u8* lifetime = nonce_g + RH_SECURE_NONCE_SIZE;
    const rh_u8* tag = lifetime + 2u;
    rh_u8 expected[RH_SECURE_TAG_SIZE];
    rh_hmac h;
    rh_hmac_begin(&h, secure->device_key, RH_SECURE_KEY_SIZE);
    rh_hmac_add(&h, RH_LABEL_SESSION, sizeof(RH_LABEL_SESSION) - 1u);
    rh_hmac_add(&h, secure->uid, RH_SECURE_UID_SIZE);
    rh_hmac_add(&h, secure->nonce_b, RH_SECURE_NONCE_SIZE);
    rh_hmac_add(&h, sid, 2u);
    rh_hmac_add(&h, nonce_g, RH_SECURE_NONCE_SIZE);
    rh_hmac_add(&h, lifetime, 2u);
    rh_hmac_end(&h, expected, RH_SECURE_TAG_SIZE);
    if (!rh_equal(expected, tag, RH_SECURE_TAG_SIZE)) {
        secure->rejected++;
        return ROBOHUB_ERR_PROTOCOL;
    }
    rh_u8 material[RH_SECURE_NONCE_SIZE * 2u];
    memcpy(material, secure->nonce_b, RH_SECURE_NONCE_SIZE);
    memcpy(material + RH_SECURE_NONCE_SIZE, nonce_g, RH_SECURE_NONCE_SIZE);
    /* The board sends up and receives down. */
    rh_hmac_begin(&h, secure->device_key, RH_SECURE_KEY_SIZE);
    rh_hmac_add(&h, RH_LABEL_UP, sizeof(RH_LABEL_UP) - 1u);
    rh_hmac_add(&h, material, sizeof(material));
    rh_hmac_end(&h, secure->key_tx, RH_SECURE_KEY_SIZE);
    rh_hmac_begin(&h, secure->device_key, RH_SECURE_KEY_SIZE);
    rh_hmac_add(&h, RH_LABEL_DOWN, sizeof(RH_LABEL_DOWN) - 1u);
    rh_hmac_add(&h, material, sizeof(material));
    rh_hmac_end(&h, secure->key_rx, RH_SECURE_KEY_SIZE);
    secure->session_id = rh_get_u16(sid);
    secure->tx_counter = 0u;
    secure->rx_counter = 0u;
    secure->expires_ms = secure->now_ms() + (rh_u32)rh_get_u16(lifetime) * 1000u;
    secure->state = RH_SECURE_ESTABLISHED;
    return ROBOHUB_OK;
}

static void rh_frame_tag(const rh_u8* key, rh_u16 msg_id, rh_u16 tx_id,
                         const rh_u8* sid_counter, const rh_u8* payload, rh_size length,
                         rh_u8 out[RH_SECURE_TAG_SIZE])
{
    rh_u8 header[4];
    rh_put_u16(header, msg_id);
    rh_put_u16(header + 2, tx_id);
    rh_hmac h;
    rh_hmac_begin(&h, key, RH_SECURE_KEY_SIZE);
    rh_hmac_add(&h, header, sizeof(header));
    rh_hmac_add(&h, sid_counter, 6u);
    rh_hmac_add(&h, payload, length);
    rh_hmac_end(&h, out, RH_SECURE_TAG_SIZE);
}

RoboHubError robohub_secure_seal(RoboHubSecure* secure, rh_u16 msg_id, rh_u16 tx_id,
                                 const rh_u8* payload, rh_size length,
                                 rh_u8* out, rh_size capacity, rh_size* out_length)
{
    if (secure == 0 || out == 0 || out_length == 0 || (payload == 0 && length > 0u)) {
        return ROBOHUB_ERR_INVALID_ARG;
    }
    if (!robohub_secure_ready(secure)) {
        return ROBOHUB_ERR_STATE;
    }
    if (length + RH_SECURE_OVERHEAD > capacity) {
        return ROBOHUB_ERR_INVALID_ARG;
    }
    secure->tx_counter++;
    rh_put_u16(out, secure->session_id);
    rh_put_u32(out + 2u, secure->tx_counter);
    if (length > 0u) {
        memmove(out + 6u, payload, length);
    }
    rh_frame_tag(secure->key_tx, (rh_u16)(msg_id | RH_SECURE_FLAG), tx_id, out, out + 6u, length,
                 out + 6u + length);
    *out_length = length + RH_SECURE_OVERHEAD;
    return ROBOHUB_OK;
}

RoboHubError robohub_secure_open(RoboHubSecure* secure, rh_u16 msg_id, rh_u16 tx_id,
                                 const rh_u8* payload, rh_size length,
                                 const rh_u8** inner, rh_size* inner_length)
{
    if (secure == 0 || payload == 0 || inner == 0 || inner_length == 0 ||
        (msg_id & RH_SECURE_FLAG) == 0u || length < RH_SECURE_OVERHEAD ||
        !robohub_secure_ready(secure)) {
        if (secure != 0) {
            secure->rejected++;
        }
        return ROBOHUB_ERR_PROTOCOL;
    }
    rh_size body = length - RH_SECURE_OVERHEAD;
    rh_u32 counter = rh_get_u32(payload + 2u);
    rh_u8 expected[RH_SECURE_TAG_SIZE];
    rh_frame_tag(secure->key_rx, msg_id, tx_id, payload, payload + 6u, body, expected);
    if (rh_get_u16(payload) != secure->session_id || counter <= secure->rx_counter ||
        !rh_equal(expected, payload + 6u + body, RH_SECURE_TAG_SIZE)) {
        secure->rejected++;
        return ROBOHUB_ERR_PROTOCOL;
    }
    secure->rx_counter = counter;
    *inner = payload + 6u;
    *inner_length = body;
    return ROBOHUB_OK;
}
