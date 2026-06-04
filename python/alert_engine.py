from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import time
import re
import subprocess

# Configuration
ES_HOST = "http://localhost:9200"
INDEX = "filebeat-*"
THRESHOLD = 5
TIME_WINDOW = 1       # minutes
CHECK_INTERVAL = 60   # seconds
RESOURCE_GROUP = "soc-lab-rg"
NSG_NAME = "soc-lab-nsg"

blocked_ips = set()   # track already blocked IPs this session

def connect():
    es = Elasticsearch(ES_HOST)
    try:
        info = es.info()
        print(f"Connected to Elasticsearch {info['version']['number']}")
        return es
    except Exception as e:
        raise Exception(f"Cannot connect: {e}")

def get_failed_logins(es, minutes_back):
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes_back)

    result = es.search(
        index=INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"match": {"message": "Invalid user"}},
                        {"range": {"@timestamp": {
                            "gte": since.isoformat(),
                            "lte": now.isoformat()
                        }}}
                    ]
                }
            },
            "size": 100
        }
    )
    return result["hits"]["hits"]

def get_next_priority():
    cmd = [
        "az", "network", "nsg", "rule", "list",
        "--resource-group", RESOURCE_GROUP,
        "--nsg-name", NSG_NAME,
        "--query", "[].priority",
        "--output", "tsv"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        priorities = [int(p) for p in result.stdout.strip().split()]
        return max(priorities) + 1
    return 100

def block_ip_in_azure(ip):
    # Check if already blocked in Azure
    check_cmd = [
        "az", "network", "nsg", "rule", "list",
        "--resource-group", RESOURCE_GROUP,
        "--nsg-name", NSG_NAME,
        "--query", f"[?sourceAddressPrefix=='{ip}'].name",
        "--output", "tsv"
    ]
    check = subprocess.run(check_cmd, capture_output=True, text=True)
    if check.returncode == 0 and check.stdout.strip():
        print(f"  [INFO] {ip} already has a block rule in Azure")
        return True

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rule_name = f"Block-{ip.replace('.', '-')}-{timestamp}"
    priority = get_next_priority()

    cmd = [
        "az", "network", "nsg", "rule", "create",
        "--resource-group", RESOURCE_GROUP,
        "--nsg-name", NSG_NAME,
        "--name", rule_name,
        "--priority", str(priority),
        "--source-address-prefix", ip,
        "--destination-address-prefix", "*",
        "--protocol", "Tcp",
        "--access", "Deny",
        "--direction", "Inbound"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"  [BLOCKED] {ip} added to NSG deny list")
        print(f"  Rule: {rule_name} — Priority: {priority}")
        return True
    else:
        print(f"  [ERROR] Failed to block {ip}: {result.stderr}")
        return False

def check_alerts(es):
    hits = get_failed_logins(es, TIME_WINDOW)

    # Count attempts per IP by parsing the message field
    ip_counts = {}
    for hit in hits:
        message = hit["_source"].get("message", "")
        match = re.search(r"Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)", message)
        if match:
            ip = match.group(1)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Fire alert for any IP exceeding the threshold
    for ip, count in ip_counts.items():
        if count > THRESHOLD:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            print(f"[ALERT] {timestamp}")
            print(f"  SSH Brute Force Detected")
            print(f"  Source IP:  {ip}")
            print(f"  Attempts:   {count} in last {TIME_WINDOW} minute(s)")
            print(f"  Threshold:  {THRESHOLD}")

            # Only block if not already blocked this session
            if ip not in blocked_ips:
                block_ip_in_azure(ip)
                blocked_ips.add(ip)
            else:
                print(f"  [INFO] {ip} already blocked this session")
            print("")

def main():
    print("SOC Alert Engine starting...")
    es = connect()
    print(f"Checking every {CHECK_INTERVAL} seconds.")
    print("")
    while True:
        check_alerts(es)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
