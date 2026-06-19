# Radio captures (pcap)

The per-run radio captures (`.pcap`, IEEE 802.15.4 frames logged by the Cooja
RadioLogger) are part of the full dataset and are **archived on Zenodo** together with
the logs and CSVs:

> Zenodo DOI: `10.5281/zenodo.XXXXXXX` (to be assigned on publication)

Each pcap shares the stem of its run's `.log`/`.csv` (see `../../schema.md`); the logs
and CSVs for all 122 runs are already in this repository under `../single/` and
`../multiattack/`. A couple of sample pcaps are included under `sample/` so the format
can be inspected without the full ~2.1 GB download.

Open with Wireshark/tshark; the 6TiSCH/TSCH and RPL dissectors decode the frames.
