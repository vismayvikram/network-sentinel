
from logger import alert


arp_tracker = {}
def detect_arp_spoofing(packet):
    try:
        packet_ip = packet["ARP"].psrc
        packet_mac = packet["ARP"].hwsrc
        
        global arp_tracker
        

        
        if packet_ip not in arp_tracker:
            arp_tracker[packet_ip] = packet_mac
            return
        
        #detection
        if arp_tracker[packet_ip] != packet_mac:
            alert("ARP_SPOOFING",packet_ip, f"ARP Spoofing detected: IP {packet_ip} is now associated with MAC {packet_mac} (previously {arp_tracker[packet_ip]})")
            arp_tracker[packet_ip] = packet_mac

    except Exception as e:
        print(f"[ERROR] in detect_arp_spoof: {str(e)}")