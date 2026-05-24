from logger import alert
import time
syn_tracker= {}
def detect_syn_flood(packet):
    try:
        packet_ip = packet["IP"].src
        current_time = time.time()
        threshold = 100  # Number of SYN packets per second to trigger alert
        time_window = 1
        cutoff = current_time - time_window

        if packet_ip not in syn_tracker:
            syn_tracker[packet_ip] = []

        while syn_tracker[packet_ip] and syn_tracker[packet_ip][0] < cutoff:
            syn_tracker[packet_ip].pop(0)

        syn_tracker[packet_ip].append(current_time)

        if len(syn_tracker[packet_ip]) > threshold:  # Threshold for SYN flood
            alert("SYN_FLOOD", packet_ip, f"SYN Flood detected with {len(syn_tracker[packet_ip])} SYN packets in {time_window} seconds")
            syn_tracker[packet_ip] = []
            return True
        else:
            return False
        
    except Exception as e:
        print(f"[ERROR] in detect_syn_flood: {str(e)}")
        return False
    