import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, conf

from modules.syn_flood import detect_syn_flood
from modules.icmp_abuse import detect_icmp_abuse
from modules.arp_spoof import detect_arp_spoofing
from modules.dns_tunnel import detect_dns_tunneling
from modules.port_scan import detect_port_scan
from modules.http_inspect import detect_http_inspection
from modules.udp_flood import detect_udp_flood
from modules.flow_manager import add_packet_to_flow, update_flow_stats, check_flow_timeout
from modules.flow_feature_extractor import extract_features, get_model_vector
from modules.botnet_traffic import detect_botnet_traffic
from modules.beaconing_detector import detect_beaconing
from modules.anomaly_detector import detect as detect_anomaly

default_interface = conf.iface
count = 0


def packet_process(packet):
    global count
    count+=1

    try:
        #ARP
        if packet.haslayer(ARP):
            detect_arp_spoofing(packet)
        
        #ICMP
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            detect_icmp_abuse(packet)
        
        #TCP
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if packet[TCP].flags & 0x02:    # SYN flag only
                detect_syn_flood(packet)
                detect_port_scan(packet) 

            #HTTP Inspection
            if packet[TCP].dport in [80, 8080] or packet[TCP].sport in [80, 8080]:
                detect_http_inspection(packet)
        
        #UDP
        if packet.haslayer(UDP) and packet.haslayer(IP):
            detect_udp_flood(packet)
        
        #DNS Tunneling
        if packet.haslayer(DNS) and packet.haslayer(IP):
            detect_dns_tunneling(packet)
        
        # Flow-based ML Detection
        flow = add_packet_to_flow(packet)
        if flow is not None:
            update_flow_stats(packet, flow)

        completed_flows = check_flow_timeout(time.time())
        for completed_flow in completed_flows:
            features = extract_features(completed_flow)
            feature_vector = get_model_vector(features)
            if feature_vector is None:
                continue

            detect_botnet_traffic(feature_vector, completed_flow['srcip'], completed_flow['dstip'])
            detect_beaconing(feature_vector, completed_flow['srcip'], completed_flow['dstip'])
            detect_anomaly(feature_vector, completed_flow['srcip'], completed_flow['dstip'])

    except Exception as ex:
        print("[!] Error processing packet: ", ex)
                



def main_nids(interface_name=None):
    interface = interface_name or default_interface
    if not interface:
        print("[!] No interface specified and no default interface found.")

    print("[*] Starting NIDS on interface:", interface)
    print("[*] Listening for packets...")
    print("[*] Press Ctrl+C to stop.")

    try:
        sniff(iface=interface, prn=packet_process, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping NIDS...")
        print("[*] Total packets captured:", count)
        print("[*] Exiting.")
        exit(0)
    except PermissionError:
        print("[!] PERMISSION DENIED: This program requires root privileges to run.")
        print("    Please run the program with elevated permissions.")
    except OSError as ex:
        print("[!] Failed to start capture:", ex)
        print("    Check that the interface exists and is valid for your OS.")


if __name__ == "__main__":
    main_nids(default_interface)
