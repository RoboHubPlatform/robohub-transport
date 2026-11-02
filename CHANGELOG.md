# Changelog

All notable changes to this module are recorded here, one section per release.

## [0.2.1] - 2026-11-02

Network transports `http` and `mqtt` are listed in the capabilities, so a deployment can select a device path the platform supplies.

## [0.2.0] - 2026-11-01

`capabilities.transports` names the byte streams this runtime can carry frames
over — UART, Console, USB, WiFi, Ethernet, Socket, RS-485, SPI and I2C. A
deployment planner intersects it with both boards' `capabilities.links`.
