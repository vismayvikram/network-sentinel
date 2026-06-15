import time
from logger import alert

dns_tracker = {}


def detect_dns_tunneling(packet):
    try:
        if not packet.haslayer("IP") or not packet.haslayer("DNS"):
            return

        if not packet.haslayer("DNSQR"):
            return

        packet_ip = packet["IP"].src
        query = packet["DNSQR"].qname.decode("utf-8", errors="ignore").lower()
        qtype = packet["DNSQR"].qtype

        suspicious_reasons = []

        #long query check
        if len(query) > 100:
            suspicious_reasons.append(f"long query ({len(query)} chars)")

        labels = [label for label in query.split(".") if label]

        #label length check
        if any(len(label) > 63 for label in labels):
            suspicious_reasons.append("label longer than 63 chars")

        #unusual query type check
        if qtype in {10, 16, 255, 252}:   #{TXT type, NULL type, ANY type, Zone transfer type}
            suspicious_reasons.append(f"unusual qtype {qtype}")

        #DNS querry rate check
        current_time = time.time()
        window_start = current_time - 5
        if packet_ip not in dns_tracker:
            dns_tracker[packet_ip] = []
        dns_tracker[packet_ip] = [ts for ts in dns_tracker[packet_ip] if ts > window_start]
        dns_tracker[packet_ip].append(current_time)

        if len(dns_tracker[packet_ip]) > 30:
            suspicious_reasons.append(f"high query rate ({len(dns_tracker[packet_ip])}/5s)")
            dns_tracker[packet_ip] = []

        if suspicious_reasons:
            details = "; ".join(suspicious_reasons)
            alert("DNS_TUNNEL", packet_ip, f"Suspicious DNS tunneling detected: {details}")

    except Exception as e:
        print(f"[ERROR] in detect_dns_tunneling: {e}")
        return