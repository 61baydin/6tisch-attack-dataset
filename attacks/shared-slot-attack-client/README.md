# TSCH Shared Cell Contention attack client

Contiki-NG / 4emac firmware for the **TSCH Shared Cell Contention** attack (`attack_type = 5`) in the
6TiSCHSet-2026 dataset. On a compromised mote it injects broadcast traffic into TSCH shared cells to hog CSMA-CA back-off. The exact parameters, onset
timing, and the telemetry it produces are documented in the paper and the top-level
`README.md`.

## Build
```bash
cd examples/tsch/rpl-udp/shared-slot-attack-client
make TARGET=exp5438
```
Requires the Contiki-NG / 4emac fork (`MAKE_MAC = MAKE_MAC_4EMAC`,
`MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC`); the Makefile pulls in
`os/services/simple-energest` and the `attacker-analyzer` telemetry module.
