import os
from datetime import datetime
LOG_FILE = "logs/alerts.log"

def alert(attack_type, packet_ip, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] [!] ALERT | {attack_type} | SRC: {packet_ip} | {details}"
    print(alert_msg)
    try:
        
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{alert_msg}\n")
        
    except PermissionError:
        print(f"[ERROR] Permission denied for {LOG_FILE}. Run with sudo.")
    except Exception as e:
        print(f"[ERROR] Failed to write log: {e}")