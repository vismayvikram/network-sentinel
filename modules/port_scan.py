import time
from logger import alert

port_tracker= {}
def detect_port_scan(packet):
    try:
        packet_ip = packet["IP"].src
        packet_port = packet["TCP"].dport
        current_time = time.time()
        threshold = 15  
        time_window = 60
        global port_tracker
        cutoff = current_time - time_window
        
        if packet_ip not in port_tracker:
            port_tracker[packet_ip] = []

        while port_tracker[packet_ip] and port_tracker[packet_ip][0][1] < cutoff:
            port_tracker[packet_ip].pop(0)
        
        port_tracker[packet_ip].append((packet_port, current_time))
        unique_count = len(set(port for port, _ in port_tracker[packet_ip]))

        if unique_count > threshold:
            attack_details = (f"Port Scan detected with {unique_count} unique ports in {time_window} seconds")
            alert("PORT_SCAN", packet_ip, attack_details)
            port_tracker[packet_ip] = []
    except Exception as e:
        print(f"[ERROR] in detect_port_scan: {str(e)}")