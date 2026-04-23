#!/usr/bin/env python3

import re
import time
import sys
import ipaddress
from collections import Counter, defaultdict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import init as colorama_init
    colorama_init()
except ImportError:
    pass


# =========================
# COLORS
# =========================
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# =========================
# HUNT RULES
# =========================
HUNT_RULES = {
    "ENCODED_POWERSHELL": {
        "patterns": [
            r"powershell.*-enc",
            r"powershell.*-encodedcommand",
            r"frombase64string",
            r"[A-Za-z0-9+/]{40,}={0,2}"
        ],
        "severity": "High",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter"
    },
    "CREDENTIAL_DUMPING": {
        "patterns": [
            r"mimikatz",
            r"sekurlsa",
            r"lsass",
            r"procdump.*lsass",
            r"sam dump",
            r"ntds\.dit"
        ],
        "severity": "High",
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping"
    },
    "PERSISTENCE_ACTIVITY": {
        "patterns": [
            r"scheduled task",
            r"schtasks",
            r"run key",
            r"startup folder",
            r"reg add .*\\run",
            r"wmic startup",
            r"crontab",
            r"/etc/cron"
        ],
        "severity": "High",
        "tactic": "Persistence",
        "technique": "Scheduled Task / Job"
    },
    "LOLBINS_USAGE": {
        "patterns": [
            r"certutil",
            r"mshta",
            r"rundll32",
            r"regsvr32",
            r"bitsadmin",
            r"wmic",
            r"powershell",
            r"cscript",
            r"wscript"
        ],
        "severity": "Medium",
        "tactic": "Defense Evasion",
        "technique": "Signed Binary Proxy Execution"
    },
    "SUSPICIOUS_NETWORK_ACTIVITY": {
        "patterns": [
            r"http://",
            r"https://",
            r"curl ",
            r"wget ",
            r"invoke-webrequest",
            r"downloadstring",
            r"pastebin",
            r"ngrok",
            r"discordapp",
            r"raw\.githubusercontent"
        ],
        "severity": "Medium",
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol"
    },
    "RANSOMWARE_HINTS": {
        "patterns": [
            r"shadow copies",
            r"vssadmin delete shadows",
            r"wbadmin delete",
            r"bcdedit",
            r"encrypt",
            r"ransom",
            r"decryptor"
        ],
        "severity": "High",
        "tactic": "Impact",
        "technique": "Data Encrypted for Impact"
    },
    "PRIVILEGE_ABUSE": {
        "patterns": [
            r"sudo su",
            r"sudo -i",
            r"runas",
            r"administrator",
            r"root login",
            r"privilege escalation",
            r"token impersonation"
        ],
        "severity": "Medium",
        "tactic": "Privilege Escalation",
        "technique": "Abuse Elevation Control Mechanism"
    },
    "DEFENSE_EVASION": {
        "patterns": [
            r"disable defender",
            r"set-mppreference",
            r"tamper protection",
            r"netsh advfirewall set",
            r"stop-service.*defender",
            r"uninstall antivirus"
        ],
        "severity": "High",
        "tactic": "Defense Evasion",
        "technique": "Impair Defenses"
    },
    "SUSPICIOUS_FILE_PATHS": {
        "patterns": [
            r"temp\\",
            r"appdata\\",
            r"programdata\\",
            r"/tmp/",
            r"/dev/shm/",
            r"\.exe",
            r"\.dll",
            r"\.ps1",
            r"\.js",
            r"\.hta"
        ],
        "severity": "Low",
        "tactic": "Defense Evasion",
        "technique": "Masquerading"
    },
    "LATERAL_MOVEMENT_HINTS": {
        "patterns": [
            r"psexec",
            r"winrm",
            r"wmic /node",
            r"remote desktop",
            r"rdp",
            r"smbexec",
            r"admin\$"
        ],
        "severity": "High",
        "tactic": "Lateral Movement",
        "technique": "Remote Services"
    }
}


# =========================
# OUTPUT HELPERS
# =========================
def print_message(message: str):
    print(message + Colors.RESET)


def ask_input(prompt: str) -> str:
    return input(Colors.YELLOW + prompt + Colors.RESET)


# =========================
# BANNER
# =========================
def print_banner():
    banner = r"""
          +------------------------------------------------------------------------------+
          |                                                                              |
          |       _____ _                    _                        _                  |
          |      /__   \ |__  _ __ ___  __ _| |_    /\  /\_   _ _ __ | |_ ___ _ __       |
          |        / /\/ '_ \| '__/ _ \/ _` | __|  / /_/ / | | | '_ \| __/ _ \ '__|      |
          |       / /  | | | | | |  __/ (_| | |_  / __  /| |_| | | | | ||  __/ |         |
          |       \/   |_| |_|_|  \___|\__,_|\__| \/ /_/  \__,_|_| |_|\__\___|_|         |
          |                                                                              |
          +------------------------------------------------------------------------------+
          |                     Threat Hunting Automation Toolkit                        |
          +------------------------------------------------------------------------------+
"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: Sajjid" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: ATT&CK-style Threat Hunting with Chained Evidence" + Colors.RESET)
    print("                                               ")


# =========================
# HELPERS
# =========================
def load_input_file(file_path: str) -> list:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as exc:
        print_message(Colors.RED + f"[!] Failed to read file: {exc}")
        sys.exit(1)


def extract_ip(line: str) -> str:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    return match.group(0) if match else "Unknown"


def extract_timestamp(line: str) -> str:
    patterns = [
        r"\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b",
        r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\b",
        r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b",
        r"\b(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(:\d{2})?)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return "Unknown"


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_geoip(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "note": "Unavailable"
    }

    if not is_public_ip(ip):
        result["note"] = "Private/Internal"
        return result

    if not REQUESTS_AVAILABLE:
        result["note"] = "requests missing"
        return result

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        data = response.json()
        if data.get("status") == "success":
            result["country"] = data.get("country", "Unknown")
            result["city"] = data.get("city", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["note"] = "Success"
        else:
            result["note"] = "Lookup Failed"
    except Exception:
        result["note"] = "Lookup Failed"

    return result


def extract_command_tokens(line: str) -> list:
    interesting = [
        "powershell", "cmd.exe", "bash", "certutil", "mshta", "rundll32", "regsvr32",
        "curl", "wget", "mimikatz", "procdump", "vssadmin", "schtasks", "wmic"
    ]
    lowered = line.lower()
    return [token for token in interesting if token in lowered]


def extract_file_indicators(line: str) -> list:
    patterns = [
        r"[A-Za-z]:\\[^\s\"']+\.(?:exe|dll|ps1|bat|js|hta|tmp)",
        r"/[^\s\"']+\.(?:sh|bin|py|so|tmp)",
        r"/tmp/[^\s\"']+",
        r"/dev/shm/[^\s\"']+"
    ]
    found = []
    for pattern in patterns:
        for match in re.findall(pattern, line, re.IGNORECASE):
            found.append(match[:70])
    return found[:5]


def confidence_for_rule(rule_name: str, details: str) -> str:
    lowered = details.lower()
    if rule_name in {"CREDENTIAL_DUMPING", "DEFENSE_EVASION", "RANSOMWARE_HINTS", "LATERAL_MOVEMENT_HINTS"}:
        return "High"
    if rule_name == "ENCODED_POWERSHELL" and ("powershell" in lowered and ("-enc" in lowered or "-encodedcommand" in lowered)):
        return "High"
    if rule_name in {"LOLBINS_USAGE", "SUSPICIOUS_NETWORK_ACTIVITY", "PRIVILEGE_ABUSE", "PERSISTENCE_ACTIVITY"}:
        return "Medium"
    return "Low"


def evidence_weight(severity: str, confidence: str) -> int:
    value = 0
    if severity == "High":
        value += 3
    elif severity == "Medium":
        value += 2
    else:
        value += 1

    if confidence == "High":
        value += 2
    elif confidence == "Medium":
        value += 1

    return value


# =========================
# ANALYSIS
# =========================
def hunt_lines(lines: list) -> dict:
    findings = []
    rule_counter = Counter()
    severity_counter = Counter()
    tactic_counter = Counter()
    confidence_counter = Counter()
    source_ip_counter = Counter()
    country_counter = Counter()
    token_counter = Counter()
    file_indicator_counter = Counter()
    chain_counter = Counter()

    line_rule_hits = []

    for line in lines:
        lowered = line.lower()
        matched_rules = []
        ip = extract_ip(line)
        timestamp = extract_timestamp(line)
        command_tokens = extract_command_tokens(line)
        file_indicators = extract_file_indicators(line)

        for token in command_tokens:
            token_counter[token] += 1

        for indicator in file_indicators:
            file_indicator_counter[indicator] += 1

        for rule_name, rule_data in HUNT_RULES.items():
            for pattern in rule_data["patterns"]:
                if re.search(pattern, lowered, re.IGNORECASE):
                    matched_rules.append(rule_name)
                    break

        if matched_rules:
            line_rule_hits.append(tuple(sorted(set(matched_rules))))

        for rule_name in matched_rules:
            rule_data = HUNT_RULES[rule_name]
            severity = rule_data["severity"]
            confidence = confidence_for_rule(rule_name, line)

            finding = {
                "rule": rule_name,
                "severity": severity,
                "timestamp": timestamp,
                "ip": ip,
                "details": line,
                "tactic": rule_data["tactic"],
                "technique": rule_data["technique"],
                "confidence": confidence,
                "command_tokens": command_tokens[:4],
                "file_indicators": file_indicators[:3],
                "evidence_weight": evidence_weight(severity, confidence)
            }

            findings.append(finding)

            rule_counter[rule_name] += 1
            severity_counter[severity] += 1
            tactic_counter[rule_data["tactic"]] += 1
            confidence_counter[confidence] += 1

            if ip != "Unknown":
                source_ip_counter[ip] += 1
                if is_public_ip(ip):
                    geo = get_geoip(ip)
                    country_counter[geo["country"]] += 1

    # Chained evidence correlation
    line_combo_counter = Counter(line_rule_hits)
    for combo, count in line_combo_counter.items():
        if len(combo) >= 2:
            chain_counter[" + ".join(combo[:3])] += count

    # Hunt storyline ranking
    findings.sort(
        key=lambda x: (
            x["evidence_weight"],
            {"High": 3, "Medium": 2, "Low": 1}.get(x["severity"], 0)
        ),
        reverse=True
    )

    return {
        "total_lines": len(lines),
        "total_findings": len(findings),
        "findings": findings,
        "rule_counter": rule_counter,
        "severity_counter": severity_counter,
        "source_ip_counter": source_ip_counter,
        "tactic_counter": tactic_counter,
        "confidence_counter": confidence_counter,
        "country_counter": country_counter,
        "token_counter": token_counter,
        "file_indicator_counter": file_indicator_counter,
        "chain_counter": chain_counter
    }


# =========================
# RENDERING
# =========================
def render_summary(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Threat Hunting Summary:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Total Input Lines", str(result["total_lines"]), Colors.WHITE),
        ("Total Findings", str(result["total_findings"]), Colors.RED if result["total_findings"] > 0 else Colors.GREEN),
        ("High Severity", str(result["severity_counter"].get("High", 0)), Colors.RED),
        ("Medium Severity", str(result["severity_counter"].get("Medium", 0)), Colors.YELLOW),
        ("Low Severity", str(result["severity_counter"].get("Low", 0)), Colors.GREEN),
        ("Unique Source IPs", str(len(result["source_ip_counter"])), Colors.CYAN),
    ]

    for label, value, color in rows:
        print(
            Colors.WHITE + "|" +
            f"{label:<38}" +
            "|" +
            color + f"{value:^15}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    print(Colors.CYAN + border + Colors.RESET)


def render_distribution_table(title: str, counter: Counter):
    print("\n" + Colors.MAGENTA + Colors.BOLD + title + ":" + Colors.RESET)
    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Value':^38}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    items = counter.most_common()
    if not items:
        print(Colors.WHITE + f"|{'None':^38}|{'0':^15}|" + Colors.RESET)
    else:
        for label, count in items:
            color = Colors.YELLOW
            if title == "Severity Distribution":
                color = Colors.GREEN
                if label == "High":
                    color = Colors.RED
                elif label == "Medium":
                    color = Colors.YELLOW
            elif title == "Confidence Distribution":
                color = Colors.GREEN
                if label == "High":
                    color = Colors.RED
                elif label == "Medium":
                    color = Colors.YELLOW

            print(
                Colors.WHITE + "|" +
                f"{str(label)[:38]:<38}" +
                "|" +
                color + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )
    print(Colors.CYAN + border + Colors.RESET)


def render_counter_table(title: str, counter: Counter, color: str, limit: int = 10):
    print("\n" + color + Colors.BOLD + title + ":" + Colors.RESET)
    border = "+-------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Value':^45}|{'Count':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    items = counter.most_common(limit)
    if not items:
        print(Colors.WHITE + f"|{'None':^45}|{'0':^15}|" + Colors.RESET)
    else:
        for value, count in items:
            display = str(value)[:45]
            print(
                Colors.WHITE + "|" +
                color + f"{display:<45}" +
                Colors.WHITE + "|" +
                color + f"{str(count):^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )
    print(Colors.CYAN + border + Colors.RESET)


def render_findings_table(findings: list, title: str, limit: int = 12):
    print("\n" + Colors.CYAN + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+---------------------------------------------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^4}|{'Severity':^9}|{'Conf':^8}|{'Rule':^24}|{'Tactic':^22}|{'IP':^16}|{'Time':^22}|{'Evidence':^35}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not findings:
        print(Colors.WHITE + f"|{'-':^4}|{'-':^9}|{'-':^8}|{'None':^24}|{'None':^22}|{'None':^16}|{'None':^22}|{'None':^35}|" + Colors.RESET)
    else:
        for idx, finding in enumerate(findings[:limit], start=1):
            sev_color = Colors.GREEN
            if finding["severity"] == "High":
                sev_color = Colors.RED
            elif finding["severity"] == "Medium":
                sev_color = Colors.YELLOW

            conf_color = Colors.GREEN
            if finding["confidence"] == "High":
                conf_color = Colors.RED
            elif finding["confidence"] == "Medium":
                conf_color = Colors.YELLOW

            evidence_text = ", ".join(finding["command_tokens"][:2] + finding["file_indicators"][:1])[:28]
            if not evidence_text:
                evidence_text = finding["details"][:28]

            print(
                Colors.WHITE + "|" +
                f"{idx:^4}" +
                "|" +
                sev_color + f"{finding['severity']:^9}" +
                Colors.WHITE + "|" +
                conf_color + f"{finding['confidence']:^8}" +
                Colors.WHITE + "|" +
                f"{finding['rule'][:24]:<24}" +
                "|" +
                Colors.CYAN + f"{finding['tactic'][:22]:^22}" +
                Colors.WHITE + "|" +
                f"{finding['ip'][:16]:^16}" +
                "|" +
                f"{finding['timestamp'][:22]:^22}" +
                "|" +
                Colors.YELLOW + f"{evidence_text:<35}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_geo_context(findings: list, limit: int = 8):
    print("\n" + Colors.CYAN + Colors.BOLD + "Geo Context for Public Hunt Sources:" + Colors.RESET)

    border = "+--------------------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^4}|{'IP':^18}|{'Country':^18}|{'City':^18}|{'ISP':^32}|{'Severity':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    public_findings = []
    seen = set()
    for finding in findings:
        if is_public_ip(finding["ip"]) and finding["ip"] not in seen:
            seen.add(finding["ip"])
            public_findings.append(finding)

    if not public_findings:
        print(Colors.WHITE + f"|{'-':^4}|{'None':^18}|{'None':^18}|{'None':^18}|{'None':^32}|{'-':^15}|" + Colors.RESET)
    else:
        for idx, finding in enumerate(public_findings[:limit], start=1):
            geo = get_geoip(finding["ip"])
            sev_color = Colors.GREEN
            if finding["severity"] == "High":
                sev_color = Colors.RED
            elif finding["severity"] == "Medium":
                sev_color = Colors.YELLOW

            print(
                Colors.WHITE + "|" +
                f"{idx:^4}" +
                "|" +
                Colors.YELLOW + f"{finding['ip'][:18]:^18}" +
                Colors.WHITE + "|" +
                f"{geo['country'][:18]:^18}" +
                "|" +
                f"{geo['city'][:18]:^18}" +
                "|" +
                f"{geo['isp'][:32]:^32}" +
                "|" +
                sev_color + f"{finding['severity']:^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Recommendations:" + Colors.RESET)
    border = "+--------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^55}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []

    if result["severity_counter"].get("High", 0) > 0:
        recommendations.append("Prioritize high-severity hunt findings first.")
        recommendations.append("Inspect evidence around execution and persistence.")
        recommendations.append("Review credential dumping and ransomware indicators.")
    elif result["severity_counter"].get("Medium", 0) > 0:
        recommendations.append("Correlate medium findings with EDR or auth logs.")
    else:
        recommendations.append("No critical hunt findings detected.")

    if result["rule_counter"].get("LATERAL_MOVEMENT_HINTS", 0) > 0:
        recommendations.append("Review remote service and lateral movement artifacts.")
    if result["rule_counter"].get("DEFENSE_EVASION", 0) > 0:
        recommendations.append("Validate that security controls remain enabled.")
    if result["chain_counter"]:
        recommendations.append("Chained evidence suggests multi-stage activity.")
    if result["file_indicator_counter"]:
        recommendations.append("Inspect suspicious file paths and dropped artifacts.")

    deduped = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)

    for idx, item in enumerate(deduped[:8], start=1):
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{item[:55]:<55}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    print(Colors.CYAN + border + Colors.RESET)


# =========================
# MAIN
# =========================
def main():
    print_banner()

    print_message(Colors.BLUE + "[i] Mode        : Threat Hunting and DFIR Artifact Review")
    print_message(Colors.BLUE + "[i] Input Type  : Text-Based Log or Artifact File")
    print_message(Colors.BLUE + "[i] Detection   : ATT&CK-style Hunt Rules + Chained Evidence")
    print_message(Colors.BLUE + "[i] Features    : Command Tokens + File Indicators + Geo Context + Hunt Chains\n")

    try:
        file_path = ask_input("Enter File Path to Hunt Through: ").strip()

        if not file_path:
            print_message(Colors.RED + "[!] No file path provided.")
            sys.exit(1)

        print()
        print_message(Colors.YELLOW + "[-] Loading Input File ...")
        lines = load_input_file(file_path)

        print_message(Colors.YELLOW + "[-] Running Hunt Rules ...")
        print_message(Colors.YELLOW + "[-] Building DFIR-style Evidence Views ...\n")

        result = hunt_lines(lines)

        render_summary(result)
        render_distribution_table("Severity Distribution", result["severity_counter"])
        render_distribution_table("Confidence Distribution", result["confidence_counter"])
        render_counter_table("Hunt Rule Hits", result["rule_counter"], Colors.YELLOW)
        render_counter_table("ATT&CK-style Tactic Distribution", result["tactic_counter"], Colors.CYAN)
        render_counter_table("Source Country Distribution", result["country_counter"], Colors.MAGENTA)
        render_counter_table("Interesting Command Tokens", result["token_counter"], Colors.RED)
        render_counter_table("Suspicious File Indicators", result["file_indicator_counter"], Colors.GREEN)
        render_counter_table("Chained Evidence Combos", result["chain_counter"], Colors.YELLOW)
        render_findings_table(result["findings"], "Top Hunt Findings", limit=12)
        render_geo_context(result["findings"])
        render_recommendations(result)

    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Threat hunt interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)
