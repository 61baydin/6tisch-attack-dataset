# 6P Cell Allocation Exhaustion attack client

Contiki-NG / 4emac firmware for the **6P Cell Allocation Exhaustion** attack (`attack_type = 6`) in the
6TiSCHSet-2026 dataset. On a compromised mote it repeatedly issues 6P ADD requests to drain the per-neighbour cell pool. The exact parameters, onset
timing, and the telemetry it produces are documented in the paper and the top-level
`README.md`.

## Build
```bash
cd examples/tsch/rpl-udp/slot-exhaustion-attack-client
make TARGET=exp5438
```
Requires the Contiki-NG / 4emac fork (`MAKE_MAC = MAKE_MAC_4EMAC`,
`MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC`); the Makefile pulls in
`os/services/simple-energest` and the `attacker-analyzer` telemetry module.
