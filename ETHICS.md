# Responsible-use statement

This repository contains **working attack implementations** (firmware patches for
seven 6TiSCH attack families) alongside the labelled dataset they produce. They are
released **solely to support defensive research**: building and benchmarking
intrusion-detection systems for IETF 6TiSCH / IEEE 802.15.4 TSCH networks.

- **Simulation only.** All attacks and data were produced in the Cooja network
  simulator on emulated motes. No physical network was attacked, and no real or
  personal data is involved.
- **No live targets.** The attack code targets a controlled, self-owned simulated
  testbed. Deploying it against networks you do not own or have explicit permission
  to test is unauthorized and likely illegal.
- **Defensive intent.** Each attack is paired with the telemetry signature it leaves,
  precisely so detectors can be trained against it. Several published defenses
  (cited in the paper) consume the released per-record features as their trigger
  signal.
- **Disclosure.** The attacks instantiate mechanisms already described in the public
  literature and IETF specifications; no previously-undisclosed vulnerability is
  released here.

By using this repository you agree to use it only for lawful, defensive, and
research purposes.
