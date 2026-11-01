# Transport

RoboHub module.

**Version:** 0.2.0

## Deployment transports

`capabilities.transports` is the vocabulary a deployment planner uses:

```yaml
capabilities:
  transports: "uart console usb wifi ethernet socket rs485 spi i2c"
```

The frame is independent of the stream; the planner only needs to know which
streams both boards can serve. A board says so in `capabilities.links` (and its
buses in `capabilities.buses`), and the keeper intersects the three sets.
