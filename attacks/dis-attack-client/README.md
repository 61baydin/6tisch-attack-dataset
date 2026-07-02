# DIS Flooding attack client

Contiki-NG / 4emac firmware for the **DIS Flooding** attack (`attack_type = 3`) in the
6TiSCHSet-2026 dataset. On a compromised mote it floods DIS solicitations to amplify cluster-wide DIO control traffic. The exact parameters, onset
timing, and the telemetry it produces are documented in the paper and the top-level
`README.md`.

## Build
```bash
cd examples/tsch/rpl-udp/dis-attack-client
make TARGET=exp5438
```
Requires the Contiki-NG / 4emac fork (`MAKE_MAC = MAKE_MAC_4EMAC`,
`MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC`); the Makefile pulls in
`os/services/simple-energest` and the `attacker-analyzer` telemetry module.
