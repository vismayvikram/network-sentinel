from logger import alert
import time
udp_tracker= {}
def detect_udp_flood(packet):
    try:
        packet_ip = packet["IP"].src
        current_time = time.time()
        threshold = 100  # Number of UDP packets per second to trigger alert
        time_window = 1
        cutoff = current_time - time_window

        if packet_ip not in udp_tracker:
            udp_tracker[packet_ip] = []

        while udp_tracker[packet_ip] and udp_tracker[packet_ip][0] < cutoff:
            udp_tracker[packet_ip].pop(0)

        udp_tracker[packet_ip].append(current_time)

        if len(udp_tracker[packet_ip]) > threshold:  # Threshold for SYN flood
            alert("UDP_FLOOD", packet_ip, f"UDP Flood detected with {len(udp_tracker[packet_ip])} UDP packets in {time_window} seconds")
            udp_tracker[packet_ip] = []
            return True
        else:
            return False
        
    except Exception as e:
        print(f"[ERROR] in detect_udp_flood: {str(e)}")
        return False