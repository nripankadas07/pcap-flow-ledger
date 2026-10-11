# Candidate brief and fair comparison — 11 October 2026

**User:** Network support engineers needing a small offline capture accounting receipt. **Painful task:** A traffic trace contains payloads and many protocols when the immediate task is per-direction captured-byte totals.

**Current alternatives:** Sniffnet, Scapy, Wireshark and captcp. **Smallest useful capability:** Read bounded classic Ethernet/IPv4 TCP pcaps and summarize directional packet, payload, wire-byte and SYN/FIN/RST counts without outputting payload bytes.

**Demand evidence:** inferred from the documented protocol/workflow and established comparable projects, not a verified request for this new product. Current comparable READMEs, representative implementation/docs and recent issue/PR lists were reviewed. Those issues do not prove demand for our feature, and no competitor absence is asserted. See [portfolio research evidence](https://github.com/nripankadas07/nripankadas07/blob/main/docs/RESEARCH_2026-10-11.json) for exact observations and code/doc URLs.

**Acceptance:** the 16 core contract tests must pass, the demo must check its known output and malformed input, and a clean installed command outside source must reproduce both success and error behavior. Scope limits remain visible in README/output. LIVE additionally requires final default-branch CI and verified docs/install path.

**Discovery:** descriptive GitHub topics, the profile chronological index, and a reproducible linked demo. No promised growth, invented users or unsolicited third-party issue promotion.

**Distinctness:** compared with all 158 existing owned repository names and today's other four briefs. Cookie routing is separate from CSP/cache/robots checks; SOA rollout arithmetic is separate from mail DNS topology and DNS blocking; expression alternatives are separate from SBOM inventory/dependency audits; startup pull-in versus ordering is separate from general migration plans; captured packet accounting is separate from live LAN delivery/network discovery. These are five independent capabilities, not subdivisions of one product.

## Live GitHub research

Queries: `pcap TCP analysis sort:stars`, `pcap sort:stars`. Observation date 2026-10-11 UTC. GitHub query results were relevance-screened; some broad queries include unrelated repositories. Highest-star relevant comparable **found** in this research: [GyulyVGC/sniffnet](https://github.com/GyulyVGC/sniffnet) (41413 stars). Coverage is limited; this is not an exhaustive global ranking. Additional established tools were inspected directly. Stars are discovery evidence, not performance.

| Comparable | Stars | Latest push observed (UTC) | Documented workflow |
| --- | ---: | --- | --- |
| [secdev/scapy](https://github.com/secdev/scapy) | 12599 | 2026-10-11T00:35:34Z | Scapy: the Python-based interactive packet manipulation program & library. |
| [wireshark/wireshark](https://github.com/wireshark/wireshark) | 9982 | 2026-10-11T03:47:33Z | Read-only mirror of Wireshark's Git repository at https://gitlab.com/wireshark/wireshark. You're welcome to submit pull requests there. |
| [hgn/captcp](https://github.com/hgn/captcp) | 115 | 2018-09-02T14:59:52Z | A open source program for TCP analysis of PCAP files |
| [GyulyVGC/sniffnet](https://github.com/GyulyVGC/sniffnet) | 41413 | 2026-10-10T03:14:16Z | Comfortably monitor your network traffic 🕵️‍♂️ |

## Workflow tradeoffs

Established alternatives have broader capabilities, documentation, examples and ecosystems; installability varies by language and platform. Ours offers a narrow one-command synthetic example and a zero-runtime-dependency Python source install. No competitor installation was timed or independently stress-tested in this run. No measured time-to-first-result, reliability, support responsiveness, performance or superiority claim. Current comparable licenses are recorded in linked research metadata; none of their implementation or prose was reused. Our license is MIT. Support is best-effort GitHub reports with no SLA.

**Limits and negative result:** Classic pcap 2.4 only, Ethernet linktype 1, complete IPv4 TCP records. Non-IPv4, non-TCP and fragmented records are explicitly counted as skipped. No pcapng, VLAN dissection, reassembly, checksum validation, retransmission deduplication, timing performance analysis or splitting reused four-tuples into connections. Retransmissions count again. Output includes IPs and ports and is not anonymous. No live capture. Broader production needs should use the established tools. Runnable local success demonstrates our behavior only.
