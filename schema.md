# Record schema

Each telemetry record is 20 comma-separated integers (inside `b'...'` in the raw
`.log`; one row per line in the clean `.csv`, with a header). Column order:

| # | Column | Meaning |
|---|--------|---------|
| 1 | `timestamp` | seconds since simulation start *(identifier, excluded from ML features)* |
| 2 | `node_id` | mote ID *(identifier, excluded from ML features)* |
| 3 | `parent_id` | RPL preferred-parent ID *(identifier, excluded from ML features)* |
| 4 | `rank` | RPL rank (distance-to-root metric) |
| 5 | `buf_occupancy` | TX-queue occupancy (% of capacity) |
| 6 | `dio_sent` | cumulative DIO messages sent |
| 7 | `dao_sent` | cumulative DAO messages sent |
| 8 | `dis_sent` | cumulative DIS messages sent |
| 9 | `nbr_count` | neighbour-table size |
| 10 | `tx_slot_count` | cumulative TX slots/cells used |
| 11 | `parent_switch_count` | cumulative RPL parent changes |
| 12 | `rssi` | last received-packet RSSI |
| 13 | `route_count` | active downstream routes through the node |
| 14 | `delta_tx` | radio TX time this interval (Energest ticks) |
| 15 | `delta_rx` | radio RX/listen time this interval (Energest ticks) |
| 16 | `app_packet_count` | cumulative application packets sent |
| 17 | `forward_ratio` | 100 × forwarded/should-forward; 100 if nothing to forward (Blackhole signature) |
| 18 | `bcast_tx` | broadcast frames sent this interval (DIS/Desync signature) |
| 19 | **`is_attacker`** | label: 0 = normal, 1 = active attacker |
| 20 | **`attack_type`** | label: 0=NONE, 1=Blackhole, 2=Decreased Rank, 3=DIS, 4=App Flooding, 5=Shared Cell, 6=6P Exhaustion, 7=Desync |

## Derived features (computed by the pipeline; not in the raw log)
- **`rank_increase`** = `rank` − parent's `rank` (exact Decreased-Rank signature; negative for the attacker).
- **`d_app`** (Δapp) = per-record increment of `app_packet_count` (instantaneous send rate; App Flooding signature).

The ML feature set is the 15 raw features (4–18) plus the 2 derived features
(17 features total); the 3 identifiers are excluded to prevent identity leakage.

## Labelling
Labels turn on at the per-attacker onset and stay on for the rest of the run.
For Blackhole, whose attack loop alternates active and passive windows, this
means some attacker-labelled rows were produced while the node forwarded
normally; the paper discusses the effect on per-record recall. In `multiattack/` runs a single log contains more than one
`attack_type` (each attacker reports its own type, on disjoint mote sets).

## File naming
- single:    `<time>_<attack>-n<NN>-<placement>-a<density>-w<id>.{log,pcap,csv}`
- baseline:  `<time>_baseline-n<NN>-w<id>.{log,pcap,csv}` (attacker-free reference run)
- multiattack: `<time>_multi-<A>+<B>-n<NN>-s<seed>-w<id>.{log,pcap,csv}`
- multiseed: `<time>_<attack>-n<NN>-<placement>-a5-s<radio_seed>-w<id>.{log,pcap,csv}`
  where `<radio_seed>` is 7331 or 9173; the published-seed (123456) runs carry no
  `-s` tag and live in `single/`.

The `.log`, `.pcap`, and `.csv` of a run share the same stem; the `.log` opens with a
`# run_metadata:` line documenting the scenario.

## Manifest columns

`manifest.csv` indexes every run. Alongside the scenario descriptors it carries
two seed columns that are easy to confuse:

| Column | Meaning |
|---|---|
| `seed` | attacker-selection seed; decides *which* motes attack in a cell |
| `radio_seed` | Cooja `<randomseed>`; decides the radio realisation of the run |

The `single/` and `multiattack/` chains use `radio_seed = 123456` throughout. The
`multiseed/` chain repeats the 42 five-attacker placement cells at
`radio_seed = 7331` and `9173`, giving three replicas per cell when combined with
the published chain.
