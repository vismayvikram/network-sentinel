# NIDS Architecture Reference

This document provides a precise, implementation-level breakdown of the pipeline: data structures, feature vector layout, model input specifications, and inter-module contracts.

---

## Pipeline Overview

```
packet_process(packet)         [main.py — called by scapy for every captured packet]
│
├─ [ARP]  detect_arp_spoofing(packet)
├─ [ICMP] detect_icmp_abuse(packet)
├─ [TCP]  detect_syn_flood(packet)          ← only if SYN flag set
├─ [TCP]  detect_port_scan(packet)          ← all TCP packets
├─ [TCP:80/8080] detect_http_inspection(packet)
├─ [UDP]  detect_udp_flood(packet)
├─ [DNS]  detect_dns_tunneling(packet)
│
├─ add_packet_to_flow(packet)               → flow dict | None
├─ update_flow_stats(packet, flow)
│
└─ check_flow_timeout(time.time())          → list[completed_flow_dict]
       │
       └─ for each completed_flow:
              features = extract_features(completed_flow)   → feature dict
              vector   = get_model_vector(features)         → list[float] len=22
              │
              ├─ detect_botnet_traffic(vector, srcip, dstip)
              ├─ detect_beaconing(vector, srcip, dstip)
              └─ detect_anomaly(vector, srcip, dstip)
```

---

## Flow Dictionary

**Key:** `(srcip: str, dstip: str, sport: int, dsport: int, proto: int)`

Bidirectionality is handled by checking the reverse tuple before creating a new entry — backward packets update the forward flow's `packets_bwd` / `bytes_bwd` counters.

**Value (flow dict):**

```python
{
    'srcip':              str,       # Original flow initiator IP
    'dstip':              str,
    'sport':              int,
    'dsport':             int,
    'proto':              int,       # 6=TCP, 17=UDP, etc.
    'start_time':         float,     # time.time() at flow creation
    'last_seen_time':     float,     # updated on every packet
    'packets_fwd':        int,       # packets from srcip
    'packets_bwd':        int,       # packets from dstip
    'bytes_fwd':          int,       # len(packet) forward
    'bytes_bwd':          int,       # len(packet) backward
    'inter_arrival_fwd':  list[float],  # delta between consecutive fwd packets
    'inter_arrival_bwd':  list[float],  # delta between consecutive bwd packets
    'last_pkt_time_fwd':  float | None,
    'last_pkt_time_bwd':  float | None,
    'first_bwd_time':     float | None, # used to estimate tcprtt
    'tcp_flags':          set[str],     # 'F' and/or 'R' if seen
}
```

---

## Feature Vector Layout

`get_model_vector()` produces a `list[float]` of **22 elements** in this exact order:

| Index | Name | Formula / Source |
|:---:|:---|:---|
| 0 | `dsport` | `flow['dsport']` |
| 1 | `proto` | `flow['proto']` |
| 2 | `dur` | `max(last_seen_time − start_time, 1e-9)` |
| 3 | `sbytes` | `flow['bytes_fwd']` |
| 4 | `dbytes` | `flow['bytes_bwd']` |
| 5 | `Spkts` | `flow['packets_fwd']` |
| 6 | `Dpkts` | `flow['packets_bwd']` |
| 7 | `smeansz` | `sbytes / Spkts` (0 if Spkts=0) |
| 8 | `dmeansz` | `dbytes / Dpkts` (0 if Dpkts=0) |
| 9 | `Sload` | `sbytes / dur` |
| 10 | `pkt_ratio` | `Spkts / (Dpkts + 1e-9)` |
| 11 | `byte_ratio` | `sbytes / (dbytes + 1e-9)` |
| 12 | `Sintpkt` | `mean(inter_arrival_fwd)` |
| 13 | `Dintpkt` | `mean(inter_arrival_bwd)` |
| 14 | `Sjit` | `stdev(inter_arrival_fwd)` |
| 15 | `Djit` | `stdev(inter_arrival_bwd)` |
| 16 | `tcprtt` | `max(first_bwd_time − start_time, 0)` |
| 17 | `is_sm_ips_ports` | `int(srcip == dstip or sport == dsport)` |
| 18 | `src_is_private` | `int(ipaddress.ip_address(srcip).is_private)` |
| 19 | `dst_is_private` | `int(ipaddress.ip_address(dstip).is_private)` |
| 20 | `src_is_loopback` | `int(ipaddress.ip_address(srcip).is_loopback)` |
| 21 | `dst_is_loopback` | `int(ipaddress.ip_address(dstip).is_loopback)` |

