# robohub-transport

Framing for a byte stream. A UART, a USB CDC pipe, an RS-485 bus and a socket all
deliver a message as bytes with no idea where it ends; this turns that stream
back into messages and hands each one to the runtime's event bus.

```
robohub-core        event bus / rpc dispatch
      ▲  validated frame
robohub-transport   COBS · Fletcher-16 · parser · counters
      ▲  raw bytes
physical driver     Pico USB CDC / ESP32 UART / STM32 SPI / socket
```

## A frame

```
msg_id      u16   which event the payload is
tx_id       u16   0 for telemetry, shared by a call and its answer
payload_len u16   N
payload     [N]   the packed bytes a schema generated
crc16       u16   Fletcher-16 over the header and the payload
```

Little-endian, then COBS-encoded, then terminated by `0x00`. COBS guarantees that
byte appears nowhere else, so the parser finds a boundary the instant it sees
one — even joining a stream half way through a frame, or after a burst of noise.
A protocol that resynchronises on a timeout is a protocol that stalls when the
timer is wrong.

## No allocation

The receive buffer is in the instance and a complete frame is decoded onto the
stack. `robohub_transport_feed_byte` never blocks and never allocates, so it is
safe to call from the interrupt or DMA callback that delivered the byte.

```c
RoboHubTransport link;
robohub_transport_init(&link, &(RoboHubTransportPhy){ .write = uart_write, .context = &uart });

/* In the UART interrupt. */
robohub_transport_feed_byte(&link, received_byte);

/* To send. */
robohub_transport_send(&link, EVENT_TEMP_READING, 0, &reading, sizeof(reading));
```

A frame that checks out is published with `robohub_core_event_publish_with_tx`,
so a handler is reached by the event its `msg_id` names, and a request and its
response can share a `tx_id`.

## Counters

`crc_errors`, `rx_packets`, `tx_packets` and `dropped` are on the instance. A link
that is dropping everything says so, which on a board with no debugger is the
difference between a wire that is wrong and a program that is.

## Building

It is a native module: `rho build` adds it as a dependency, and it builds on its
own with CMake for the host tests.

## License

MIT. See `LICENSE`.
