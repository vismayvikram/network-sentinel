# Hybrid Machine Learning Network Intrusion Detection System (NIDS)

## Executive Summary
This project implements a high-performance, hybrid Network Intrusion Detection System (NIDS) that combines real-time rule-based signature matching with advanced flow-based machine learning inference. Designed for portability and robustness, the system monitors network traffic at the packet level to provide immediate alerts for known attack signatures while aggregating traffic into behavioral "flows" for complex anomaly and botnet detection.

---

##  System Architecture
The NIDS operates on a multi-stage pipeline designed to minimize latency while maximizing detection depth:

1.  **Ingestion Layer:** Raw packet capture utilizing `Scapy` to hook into network interfaces.
2.  **Immediate Rule Engine:** Stateless analysis of packets for instant detection of ARP, ICMP, and TCP/UDP flood attacks.
3.  **Flow Management:** Aggregation of packets into stateful "flows" based on a 5-tuple identifier (Src IP, Dst IP, SPort, DPort, Protocol).
4.  **Feature Extraction:** Conversion of raw flow data into a 21-dimension feature vector.
5.  **ML Inference Layer:** Asynchronous behavioral analysis using trained Random Forest and Isolation Forest models.
6.  **Unified Alerting:** Centralized logging of security events with detailed forensic metadata.

---

##  Detection Capabilities

### **Rule-Based Detection (Instantaneous)**
*   **ARP Spoofing:** Detects MITM attempts by tracking IP-MAC binding inconsistencies.
*   **ICMP Abuse:** Identifies ping floods and abnormal payload sizes.
*   **TCP SYN & UDP Flooding:** Monitors connection attempt rates to mitigate DoS/DDoS.
*   **Port Scanning:** Tracks horizontal and vertical scanning patterns across sliding time windows.
*   **Deep Packet Inspection (DPI):** 
    *   **SQL Injection (SQLi):** Signature matching for common SQL exploit patterns in HTTP payloads.
    *   **Cross-Site Scripting (XSS):** Detection of malicious script injection attempts.
*   **DNS Tunneling:** Analyzes query entropy, label length, and request frequency to detect covert data exfiltration.

### **Machine Learning Detection (Behavioral)**
*   **Botnet Detection:** Identifies Command & Control (C2) communication patterns.
*   **Beaconing Activity:** Flags periodic heartbeats characteristic of advanced persistent threats (APTs).
*   **Anomaly Detection:** An unsupervised approach using Isolation Forests to detect "Zero-Day" deviations from benign network baselines.

---

##  Design Philosophy: Feature Engineering & Generalization
Unlike traditional models that overfit to specific network environments, this system is built on a **Topology Agnostic** philosophy:

*   **Throughput Invariance:** Raw byte and packet counts are intentionally excluded. These metrics add unnecessary noise and vary wildly between different hardware.
*   **Behavioral Ratios:** The model focuses on **Packet and Byte Ratios**. This prioritizes the *symmetry* of communication—a high-signal indicator of botnet behavior—over simple volume.
*   **Network Portability:** Models are not trained on raw IP addresses. Instead, they utilize categorical flags (`is_private`, `is_loopback`). This ensures a model trained in one environment can be deployed on any network without re-training.
*   **Noise Reduction:** By focusing on standardized inter-arrival times (jitter) and flow duration, the system ignores transient network spikes to reduce False Positive Rates (FPR).

---

##  Model Performance
The machine learning components were trained on a diversified dataset including **CIC-IDS-2017**, **UNSW-NB15**, and real-world network traffic.

| Model | Algorithm | Training Data | Cross-Validated Metrics |
|:---|:---|:---|:---|
| **Botnet Detector** | Random Forest (200 est.) | CIC-IDS-2017 Friday + home flows | Precision: 94.1% · Recall: 99.1% · F1: 96.6% |
| **Beaconing Detector** | Random Forest (100 est.) | UNSW-NB15 + home captures | Precision: 89.5% · Recall: 85.2% · F1: 87.3% |
| **Anomaly Detector** | Isolation Forest (200 est., contamination=0.05) | CIC-IDS + UNSW-NB15 + home flows | Detection Rate: **94.3%** · FPR: 3.2% |

## 🚀 Getting Started

### Prerequisites
*   Python 3.10+
*   **Windows:** Npcap (installed with "WinPcap compatibility mode")
*   **Linux:** `libpcap` and root privileges

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/nids-project.git
   cd nids-project
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Execution
Run the system with Administrative/Sudo privileges to allow raw socket access:
```bash
python main.py
```

---

## 📁 Project Structure
*   `main.py`: The system entry point and packet sniffer orchestration.
*   `modules/`: Contains individual logic for rule-based detectors and ML wrappers.
*   `ML/`: 
    *   `models/`: Serialized `.pkl` files for production inference.
    *   `training/`: Comprehensive Jupyter Notebooks detailing the data science lifecycle.
*   `logger.py`: Unified forensic logging system.
*   `home_network_data/`: Local baseline traffic captures for anomaly calibration.

---

## 📝 Logging & Forensics
All alerts are logged to `logs/alerts.log` in the following format:
`[Timestamp] [!] ALERT | [Attack_Type] | SRC: [IP_Address] | [Technical_Details]`

---
