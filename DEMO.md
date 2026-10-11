# Runnable demo

```bash
python demo.py
python pcap_flow_ledger.py example.pcap
```

`demo.py` checks a synthetic success and malformed-input rejection. The installed command uses the same arguments.

## Input contract

```text
The example contains synthetic TEST-NET IPv4 endpoints 192.0.2.1 and 192.0.2.2. Two TCP frames, 57 + 56 wire bytes, payload lengths 3 and 2, opposite directions. It is generated in test_contract.py; not a real captured trace.
```

Inspect `test_contract.py` for independently specified expected outcomes, including boundary failures. Classic pcap 2.4 only, Ethernet linktype 1, complete IPv4 TCP records. Non-IPv4, non-TCP and fragmented records are explicitly counted as skipped. No pcapng, VLAN dissection, reassembly, checksum validation, retransmission deduplication, timing performance analysis or splitting reused four-tuples into connections. Retransmissions count again. Output includes IPs and ports and is not anonymous. No live capture.
