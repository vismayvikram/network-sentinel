from logger import alert
import time
icmp_tracker= {}
def detect_icmp_abuse(packet):
    try:
        packet_ip = packet["IP"].src

        current_time = time.time()
        time_window = 1
        cutoff = current_time - time_window

        icmp_payload_size = len(packet["ICMP"].payload)

        if packet_ip not in icmp_tracker:
            icmp_tracker[packet_ip] = []
        
        while icmp_tracker[packet_ip] and icmp_tracker[packet_ip][0] < cutoff:
            icmp_tracker[packet_ip].pop(0)
        
        icmp_tracker[packet_ip].append(current_time)
        
        if len(icmp_tracker[packet_ip]) > 20: # threshold for ICMP abuse
            alert("ICMP_ABUSE", packet_ip, f"ICMP Flood detected from {packet_ip}")
            icmp_tracker[packet_ip] = []
        elif icmp_payload_size > 1460:
            alert("ICMP_ABUSE", packet_ip, f"Large ICMP packet detected with size {icmp_payload_size} bytes from {packet_ip}")
            
    except Exception as e:
        print(f"[ERROR] in detect_icmp_abuse: {str(e)}")