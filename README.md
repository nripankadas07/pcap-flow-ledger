# pcap-flow-ledger

Read bounded classic Ethernet/IPv4 TCP pcaps and summarize directional packet, payload, wire-byte and SYN/FIN/RST counts without outputting payload bytes.

For network support engineers needing a small offline capture accounting receipt. A traffic trace contains payloads and many protocols when the immediate task is per-direction captured-byte totals.

## Quickstart

Python 3.10 or newer. No runtime dependencies or service account. Build tooling downloads require access to PyPI; this repository is not published on PyPI.

```bash
git clone https://github.com/nripankadas07/pcap-flow-ledger.git
cd pcap-flow-ledger
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/pcap-flow-ledger example.pcap
```

Windows: use `.venv\Scripts\python.exe` and `.venv\Scripts\pcap-flow-ledger.exe` instead. Windows is not part of the tested CI matrix.

The supplied example is synthetic. JSON success exits 0, including valid findings such as unmet quorum, ineligible cookie or an ordering cycle; malformed or unsupported input exits 2 with an `error` field. Argument usage errors use argparse's stderr. No input files or live services are modified.

## Scope and limits

Classic pcap 2.4 only, Ethernet linktype 1, complete IPv4 TCP records. Non-IPv4, non-TCP and fragmented records are explicitly counted as skipped. No pcapng, VLAN dissection, reassembly, checksum validation, retransmission deduplication, timing performance analysis or splitting reused four-tuples into connections. Retransmissions count again. Output includes IPs and ports and is not anonymous. No live capture.

Input limits: 32 MiB file, 100,000 packet records and 10,000 flows.

## Inspectable evidence

- [Demo and input schema](DEMO.md)
- [Candidate brief and comparisons](RESEARCH.md)
- [Validation and untested behavior](VALIDATION.md)
- [Build instructions](BUILDING.md)
- [Security reporting](SECURITY.md) and [support/contribution guidance](SUPPORT.md)

MIT; original implementation. No competitor code or branding copied. No speed, adoption or superiority claim. CI executes core regressions, the demo, a fresh wheel installation outside source and the documented source installation on Python 3.10, 3.12 and 3.14.
