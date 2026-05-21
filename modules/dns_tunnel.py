import time
from logger import alert
dns_tracker= {}
def detect_dns_tunneling(packet):
    try:
        packet_ip = packet["IP"].src

        if not packet.haslayer("DNS"):
            return

        if packet.haslayer("DNSQR"):
            query = packet["DNSQR"].qname.decode('utf-8', errors='ignore').lower()
        
        if len(query) > 60:
            alert("DNS_TUNNEL", packet_ip, f"Suspiciously long DNS query ({len(query)} chars): {query}")

        current_time = time.time()
        time_window = 5  
        cutoff = current_time - time_window
        threshold = 30  
        if packet_ip not in dns_tracker:
            dns_tracker[packet_ip] = []
                
        while dns_tracker[packet_ip] and dns_tracker[packet_ip][0] < cutoff:
            dns_tracker[packet_ip].pop(0)
                
        dns_tracker[packet_ip].append(current_time)
        
        if len(dns_tracker[packet_ip]) > threshold:
            alert("DNS_TUNNEL", packet_ip, f"High volume DNS requests ({len(dns_tracker[packet_ip])} in {time_window}s)")
            dns_tracker[packet_ip] = []  # Reset tracker
    except Exception as e:
        print(f"[ERROR] in detect_dns_tunneling: {str(e)}")