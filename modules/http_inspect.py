from logger import alert
sql_patterns = ["' OR 1=1", "UNION SELECT", "DROP TABLE", "SELECT * FROM"]
xss_patterns = ["<script>", "javascript:", "onerror="]

def detect_http_inspection(packet):
    try:
        packet_ip = packet["IP"].src
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load.decode('utf-8', errors='ignore').lower()

            #Detect malicious patterns
            for pattern in sql_patterns:
                if pattern.lower() in payload:
                    alert("SQL_INJECTION", packet_ip, f"SQL Injection detected via HTTP")
                    return
            
            for pattern in xss_patterns:
                if pattern.lower() in payload:
                    alert("XSS", packet_ip, f"XSS attack detected via HTTP")
                    return
    except Exception as e:
        print(f"[ERROR] in detect_http_inspection: {str(e)}")        
