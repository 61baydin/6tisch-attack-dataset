# Border-router client (benign node)

Contiki-NG / 4emac firmware for the regular (benign) client node used in the
6TiSCHSet-2026 dataset; it is the normal, non-attacking client node firmware and reports telemetry via the `attacker-analyzer`
module. Build:
```bash
cd examples/tsch/rpl-udp/client
make TARGET=exp5438
```
