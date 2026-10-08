/**
 * @file transport.h
 * @brief Framing for a byte stream: COBS, a CRC, and a byte-at-a-time parser.
 *
 * A UART, a USB CDC pipe, an RS-485 bus and a socket all do the same thing to a
 * message: they deliver it as bytes, with no idea where one message ends and the
 * next begins. This module turns that stream back into messages — framed,
 * length-checked, integrity-checked — and hands each one to the runtime's event
 * bus.
 *
 * COBS, not a start pattern or a timeout. Every frame is byte-stuffed so the
 * delimiter 0x00 appears only between frames, which lets the parser find a
 * boundary the instant it sees one, even if it joined the stream half way
 * through a frame or after a burst of noise. A protocol that resynchronises on
 * a timer is a protocol that stalls when the timer is wrong.
 *
 * No allocation. The receive buffer is in the instance, the frame is decoded
 * onto the stack, and the same functions run from an interrupt, a DMA callback
 * or a thread. `feed_byte` never blocks and never calls malloc.
 *
 * @project RoboHub Platform
 * @author Aurel Miron
 * @version 0.1
 * @date 2026
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef INCLUDE_ROBOHUB_TRANSPORT_H
#define INCLUDE_ROBOHUB_TRANSPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma once

#include "types.h"
#include "error.h"
#include "robohub/core/events.h"

/* The resolved configuration, when a build wrote one; a host test has none. */
#if defined(__has_include)
#  if __has_include("autoconf.h")
#    include "autoconf.h"
#  endif
#endif

/** The largest COBS-encoded frame accepted or produced, in bytes. */
#ifndef RH_TRANSPORT_MAX_FRAME_SIZE
#  ifdef CONFIG_RH_TRANSPORT_MAX_FRAME_SIZE
#    define RH_TRANSPORT_MAX_FRAME_SIZE CONFIG_RH_TRANSPORT_MAX_FRAME_SIZE
#  else
#    define RH_TRANSPORT_MAX_FRAME_SIZE 256u
#  endif
#endif

/** The byte that separates frames; COBS guarantees it appears nowhere else. */
#define RH_TRANSPORT_DELIMITER 0x00u
/** msg_id, tx_id and payload_len, little-endian. */
#define RH_TRANSPORT_HEADER_SIZE 6u
/** The integrity check that follows the payload. */
#define RH_TRANSPORT_CRC_SIZE 2u
/** The smallest frame that carries a header and a check. */
#define RH_TRANSPORT_MIN_FRAME (RH_TRANSPORT_HEADER_SIZE + RH_TRANSPORT_CRC_SIZE)

/* -------------------------------------------------------------------------- */
/*  Physical link                                                             */
/* -------------------------------------------------------------------------- */

/**
 * @brief The wire a transport is on.
 *
 * One call, and it is the platform's: writing bytes to a USB CDC endpoint, a
 * UART, an RS-485 transceiver or a socket. The transport neither knows nor asks
 * which, which is what lets one framing layer carry all of them.
 */
typedef struct RoboHubTransportPhy {
    /** Write bytes to the link; return 0 on success, -1 on failure. */
    int (*write)(const rh_u8* data, rh_size length, void* context);
    /** Whatever `write` needs to reach the link. */
    void* context;
} RoboHubTransportPhy;

/* -------------------------------------------------------------------------- */
/*  Transport instance                                                        */
/* -------------------------------------------------------------------------- */

/**
 * @brief One framed channel over one byte stream.
 *
 * A value the caller owns. The receive buffer is part of it, so the instance's
 * size is the maximum frame size and it belongs in static storage or on a
 * stack that can hold it — not in an interrupt's.
 */
typedef struct RoboHubTransport {
    RoboHubTransportPhy phy;
    rh_u8   rx[RH_TRANSPORT_MAX_FRAME_SIZE];
    rh_size rx_length;
    /** Frames whose check did not match. */
    rh_u32  crc_errors;
    /** Frames delivered to the bus. */
    rh_u32  rx_packets;
    /** Frames handed to the link. */
    rh_u32  tx_packets;
    /** Frames dropped for being too long or malformed. */
    rh_u32  dropped;
} RoboHubTransport;

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

/** Bind a transport to a link. The link must outlive the transport. */
RoboHubError robohub_transport_init(RoboHubTransport* transport,
                                    const RoboHubTransportPhy* phy);

/**
 * @brief Offer one byte from the link to the parser.
 *
 * Safe to call from an interrupt. When the byte completes a frame and the frame
 * checks out, the payload is published on the event bus before this returns,
 * with `msg_id` as the event and `tx_id` as the transaction.
 */
void robohub_transport_feed_byte(RoboHubTransport* transport, rh_u8 byte);

/** Offer a buffer of bytes to the parser. */
void robohub_transport_feed(RoboHubTransport* transport, const rh_u8* data, rh_size length);

/**
 * @brief Frame a payload and write it to the link.
 *
 * Returns `ROBOHUB_ERR_INVALID_ARG` when the payload cannot fit a frame. The
 * caller owns `payload`; it is read here and not kept.
 */
RoboHubError robohub_transport_send(RoboHubTransport* transport,
                                    robohub_event_id msg_id,
                                    rh_u16 tx_id,
                                    const void* payload,
                                    rh_u16 payload_len);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_ROBOHUB_TRANSPORT_H */
