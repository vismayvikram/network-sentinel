import time
from logger import alert
dns_tracker= {}
def detect_dns_tunneling(packet):
    try:
        packet_ip = packet["IP"].src

        if not packet.haslayer("DNS"):
            return 

        query = ""
        if packet.haslayer("DNSQR"):
            query = packet["DNSQR"].qname.decode('utf-8', errors='ignore').lower()
        if query and len(query) > 100:
            alert("DNS_TUNNEL", packet_ip, f"Suspiciously long DNS query ({len(query)} chars): {query}")
            return
        
        current_time = time.time()
        time_window = 5  
        cutoff = current_time - time_window
        threshold = 30  
        
        if packet_ip not in dns_tracker:
            dns_tracker[packet_ip] = []
        
        dns_tracker[packet_ip] = [ts for ts in dns_tracker[packet_ip] if ts > cutoff]

        if len(dns_tracker[packet_ip]) > threshold:
            alert("DNS_TUNNEL", packet_ip, f"High volume DNS requests ({len(dns_tracker[packet_ip])} in {time_window}s)")
            dns_tracker[packet_ip] = [] 
            return
        
        dns_tracker[packet_ip].append(current_time)
    except Exception as e:
        print(f"[ERROR] in detect_dns_tunneling: {str(e)}")
        return