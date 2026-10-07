from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import argparse
import json
import os
import time
import re
import subprocess
import ipaddress
import requests

# Configuration
ES_HOST = "http://localhost:9200"   # lab only: security disabled; production would use https + API key
INDEX = "filebeat-*"
THRESHOLD = 5
TIME_WINDOW = 1       # minutes
CHECK_INTERVAL = 60   # seconds
MAX_EVENTS = 1000     # events pulled per check (a terms aggregation would scale better)
RESOURCE_GROUP = "soc-lab-rg"
NSG_NAME = "soc-lab-nsg"
MIN_NSG_PRIORITY = 100  # lowest priority number Azure allows (lower number = evaluated first)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")  # export it; never commit a key

blocked_ips = set()   # IPs this session has confirmed blocked

def connect():
    es = Elasticsearch(ES_HOST)
    try:
        info = es.info()
        print(f"Connected to Elasticsearch {info['version']['number']}")
        return es
    except Exception as e:
        raise Exception(f"Cannot connect: {e}")

def is_private_ip(ip):
    """Check if an IP is a private/internal address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def check_ip_reputation(ip):
    """Query AbuseIPDB for threat intel on an IP address."""
    if is_private_ip(ip):
        return {
            "skipped": True,
            "reason": f"{ip} is a private IP — AbuseIPDB only tracks public IPs. In production this would query real attacker IPs."
        }
    if not ABUSEIPDB_API_KEY:
        return {"skipped": True, "reason": "ABUSEIPDB_API_KEY not set — enrichment skipped"}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "skipped": False,
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "last_reported": data["lastReportedAt"]
        }
    except Exception as e:
        return {"skipped": True, "reason": f"API error: {e}"}

def get_failed_logins(es, minutes_back):
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes_back)

    result = es.search(
        index=INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"message": "Invalid user"}},
                        {"range": {"@timestamp": {
                            "gte": since.isoformat(),
                            "lte": now.isoformat()
                        }}}
                    ]
                }
            },
            "size": MAX_EVENTS
        }
    )
    return result["hits"]["hits"]

def dedupe_hits(hits):
    """Drop events indexed more than once.

    If the same log line arrives through two Filebeat inputs it is indexed twice,
    which would double the attempt count. The same line always has the same file
    path and byte offset, so use those as the identity (message + timestamp as a
    fallback when the fields are missing).
    """
    seen = set()
    unique = []
    for hit in hits:
        src = hit["_source"]
        path = src.get("log", {}).get("file", {}).get("path")
        offset = src.get("log", {}).get("offset")
        key = (path, offset) if path is not None and offset is not None \
            else (src.get("message"), src.get("@timestamp"))
        if key not in seen:
            seen.add(key)
            unique.append(hit)
    return unique

def run_az(args):
    """Run an Azure CLI command and return parsed JSON (or None on failure)."""
    result = subprocess.run(["az"] + args + ["--output", "json"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [ERROR] az {' '.join(args[:4])} failed: {result.stderr.strip()}")
        return None
    return json.loads(result.stdout) if result.stdout.strip() else None

def list_inbound_rules():
    rules = run_az(["network", "nsg", "rule", "list",
                    "--resource-group", RESOURCE_GROUP,
                    "--nsg-name", NSG_NAME])
    if rules is None:
        return None
    return [r for r in rules if r.get("direction") == "Inbound"]

def allow_ceiling(rules):
    """Lowest priority number used by an inbound Allow rule.

    NSG rules are evaluated lowest number first and the first match wins, so a
    Deny only takes effect if its number is below every Allow it must beat.
    """
    allows = [r["priority"] for r in rules if r.get("access") == "Allow"]
    return min(allows) if allows else 4096

def source_matches(rule, ip):
    return rule.get("sourceAddressPrefix") == ip or ip in (rule.get("sourceAddressPrefixes") or [])

def covers_all_ports(rule):
    ranges = rule.get("destinationPortRanges") or []
    single = rule.get("destinationPortRange")
    return single == "*" or "*" in ranges

def find_effective_block(rules, ip):
    """Return an existing Deny rule for this IP that actually blocks it.

    A rule only counts if it covers all ports and protocols and sits ahead of
    the allow rules. The June 8 rule (priority 1201, port 80) does not count.
    """
    ceiling = allow_ceiling(rules)
    for r in rules:
        if (r.get("access") == "Deny"
                and source_matches(r, ip)
                and r.get("protocol") == "*"
                and covers_all_ports(r)
                and r["priority"] < ceiling):
            return r
    return None

def get_next_priority(rules):
    """Lowest free priority between 100 and the first Allow rule."""
    used = {r["priority"] for r in rules}
    ceiling = allow_ceiling(rules)
    for p in range(MIN_NSG_PRIORITY, ceiling):
        if p not in used:
            return p
    raise RuntimeError(f"No free NSG priority below {ceiling}; a block rule would never be evaluated")

def block_ip_in_azure(ip):
    rules = list_inbound_rules()
    if rules is None:
        return False

    existing = find_effective_block(rules, ip)
    if existing:
        print(f"  [INFO] {ip} already blocked by {existing['name']} (priority {existing['priority']})")
        return True

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rule_name = f"Block-{ip.replace('.', '-')}-{timestamp}"
    try:
        priority = get_next_priority(rules)
    except RuntimeError as e:
        print(f"  [ERROR] {e}")
        return False

    created = run_az([
        "network", "nsg", "rule", "create",
        "--resource-group", RESOURCE_GROUP,
        "--nsg-name", NSG_NAME,
        "--name", rule_name,
        "--priority", str(priority),
        "--direction", "Inbound",
        "--access", "Deny",
        "--protocol", "*",                    # all protocols, not just TCP
        "--source-address-prefixes", ip,
        "--source-port-ranges", "*",
        "--destination-address-prefixes", "*",
        "--destination-port-ranges", "*",     # without this the CLI defaults to port 80
        "--description", "Auto-block from alert_engine.py (SSH brute force)"
    ])
    if created is None:
        return False

    print(f"  [BLOCKED] {ip} denied on all ports and protocols")
    print(f"  Rule: {rule_name} — Priority: {priority} (ahead of allow rules starting at {allow_ceiling(rules)})")
    return True

def unblock_ip(ip):
    """Delete every Deny rule for an IP (lab reset after a test)."""
    rules = list_inbound_rules()
    if rules is None:
        return
    targets = [r for r in rules if r.get("access") == "Deny" and source_matches(r, ip)]
    if not targets:
        print(f"No Deny rules found for {ip}")
    for r in targets:
        subprocess.run(["az", "network", "nsg", "rule", "delete",
                        "--resource-group", RESOURCE_GROUP, "--nsg-name", NSG_NAME,
                        "--name", r["name"]], check=False)
        print(f"Deleted {r['name']} (priority {r['priority']})")

def check_alerts(es):
    hits = dedupe_hits(get_failed_logins(es, TIME_WINDOW))

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

            # Threat intel enrichment
            intel = check_ip_reputation(ip)
            if intel["skipped"]:
                print(f"  [THREAT INTEL] {intel['reason']}")
            else:
                print(f"  [THREAT INTEL] Abuse Score:   {intel['abuse_score']}/100")
                print(f"  [THREAT INTEL] Total Reports: {intel['total_reports']}")
                print(f"  [THREAT INTEL] Country:       {intel['country']}")
                print(f"  [THREAT INTEL] ISP:           {intel['isp']}")
                print(f"  [THREAT INTEL] Last Reported: {intel['last_reported']}")
                if intel["abuse_score"] > 50:
                    print(f"  *** HIGH RISK — KNOWN MALICIOUS ACTOR ***")

            # Block if not already blocked; only remember it once Azure confirms
            if ip in blocked_ips:
                print(f"  [INFO] {ip} already blocked this session")
            elif block_ip_in_azure(ip):
                blocked_ips.add(ip)
            print("")

def main():
    parser = argparse.ArgumentParser(description="SSH brute-force detection and Azure NSG auto-block")
    parser.add_argument("--unblock", metavar="IP", help="delete Deny rules for IP and exit")
    args = parser.parse_args()

    if args.unblock:
        unblock_ip(args.unblock)
        return

    print("SOC Alert Engine starting...")
    es = connect()
    print(f"Checking every {CHECK_INTERVAL} seconds.")
    print("")
    while True:
        check_alerts(es)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
