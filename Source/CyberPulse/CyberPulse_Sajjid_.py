#!/usr/bin/env python3

import time
import sys
import socket
import ipaddress
import re
from urllib.parse import urlparse, unquote

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
# CONSTANTS
# =========================
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify", "account",
    "signin", "bank", "payment", "confirm", "unlock",
    "password", "admin", "auth", "support", "invoice",
    "reset", "wallet", "crypto", "bonus", "gift", "reward"
]

SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".tk", ".xyz", ".top", ".buzz",
    ".click", ".gq", ".ml", ".work", ".shop", ".rest",
    ".cam", ".monster", ".zip", ".mov"
}

HIGH_VALUE_BRANDS = [
    "microsoft", "google", "apple", "paypal", "amazon",
    "bank", "chase", "wellsfargo", "office365", "outlook",
    "facebook", "instagram", "whatsapp", "telegram", "github"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "buff.ly", "cutt.ly", "ow.ly", "tiny.one", "rebrand.ly"
}

COMMON_SAFE_PORTS = {80, 443, 53, 25}
COMMON_RISKY_PORTS = {21, 23, 445, 3389, 2375, 3306, 5432, 6379, 9200, 27017}


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

        +-----------------------------------------------------------------+
        |       _____       _                ______      _                |
        |      /  __ \     | |               | ___ \    | |               |
        |      | /  \/_   _| |__   ___ _ __  | |_/ /   _| |___  ___       |
        |      | |   | | | | '_ \ / _ \ '__| |  __/ | | | / __|/ _ \      |
        |      | \__/\ |_| | |_) |  __/ |    | |  | |_| | \__ \  __/      |
        |       \____/\__, |_.__/ \___|_|    \_|   \__,_|_|___/\___|      |
        |              __/ |                                              |
        |             |___/                                               |
        +-----------------------------------------------------------------+
        |              IOC / Domain / URL Triage Analyzer                 |
        +-----------------------------------------------------------------+
        
"""
    print(Colors.RED + banner + Colors.RESET)
    print(Colors.CYAN + "[*] Internship Portfolio Edition" + Colors.RESET)
    print(Colors.GREEN + "[*] Author: StellarSajjid23" + Colors.RESET)
    print(Colors.YELLOW + "[*] Engine: IOC / Domain / URL Heuristic Analysis" + Colors.RESET)
    print("                                                     ")


# =========================
# BASIC DETECTION HELPERS
# =========================
def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+", value))


def is_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def normalize_input(target: str) -> str:
    return target.strip()


def resolve_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Resolution Failed"


def reverse_dns_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Not Found"


def get_ip_category(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return "Private"
        if ip_obj.is_loopback:
            return "Loopback"
        if ip_obj.is_multicast:
            return "Multicast"
        if ip_obj.is_reserved:
            return "Reserved"
        if ip_obj.is_global:
            return "Public"
        return "Unknown"

    except ValueError:
        return "Invalid"


# =========================
# GEOIP
# =========================
def get_ip_geolocation(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "zip": "Unknown",
        "timezone": "Unknown",
        "isp": "Unknown",
        "lat": "Unknown",
        "lon": "Unknown",
        "note": "Unavailable"
    }

    if get_ip_category(ip) != "Public":
        result["note"] = "Private/Internal/Non-Public"
        return result

    if not REQUESTS_AVAILABLE:
        result["note"] = "requests missing"
        return result

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            result["country"] = data.get("country", "Unknown")
            result["region"] = data.get("regionName", "Unknown")
            result["city"] = data.get("city", "Unknown")
            result["zip"] = data.get("zip", "Unknown")
            result["timezone"] = data.get("timezone", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["lat"] = str(data.get("lat", "Unknown"))
            result["lon"] = str(data.get("lon", "Unknown"))
            result["note"] = "Success"
        else:
            result["note"] = "Lookup Failed"

    except Exception:
        result["note"] = "Lookup Failed"

    return result


# =========================
# DOMAIN / URL HEURISTICS
# =========================
def get_registered_like_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def count_subdomains(host: str) -> int:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def check_suspicious_keywords(text: str) -> list:
    lowered = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]


def check_suspicious_tld(domain: str) -> bool:
    lowered = domain.lower()
    return any(lowered.endswith(tld) for tld in SUSPICIOUS_TLDS)


def contains_punycode(domain: str) -> bool:
    return "xn--" in domain.lower()


def contains_direct_ip_host(host: str) -> bool:
    return is_ip_address(host)


def has_excessive_digits(text: str) -> bool:
    digits = sum(1 for c in text if c.isdigit())
    return digits >= 5


def has_long_hostname(host: str) -> bool:
    return len(host) > 35


def has_many_hyphens(host: str) -> bool:
    return host.count("-") >= 3


def looks_like_brand_impersonation(host: str) -> list:
    lowered = host.lower()
    hits = []

    for brand in HIGH_VALUE_BRANDS:
        if brand in lowered:
            registered = get_registered_like_domain(host)
            if brand not in registered:
                hits.append(brand)
            elif registered.startswith(brand + "-") or registered.endswith("-" + brand):
                hits.append(brand)

    return sorted(set(hits))


def is_shortener_domain(host: str) -> bool:
    return host.lower() in SHORTENER_DOMAINS


def path_risk_factors(path: str, query: str) -> list:
    factors = []
    combined = (path + "?" + query).lower()

    suspicious_path_terms = [
        "login", "signin", "verify", "update", "secure", "account",
        "reset", "invoice", "payment", "wallet", "password", "auth"
    ]

    if len(path) > 50:
        factors.append("Long URL path")

    if "%" in combined:
        factors.append("Encoded characters in path/query")

    if "@" in combined:
        factors.append("@ symbol in path/query")

    if re.search(r"[A-Za-z0-9]{30,}", combined):
        factors.append("Long token-like string in path/query")

    for term in suspicious_path_terms:
        if term in combined:
            factors.append(f"Suspicious path term: {term}")
            break

    return factors


def detect_url_scheme_risk(parsed) -> list:
    risks = []

    if parsed.scheme.lower() == "http":
        risks.append("Uses HTTP instead of HTTPS")

    if parsed.port and parsed.port not in COMMON_SAFE_PORTS:
        if parsed.port in COMMON_RISKY_PORTS:
            risks.append(f"Uses high-risk port {parsed.port}")
        else:
            risks.append(f"Uses uncommon port {parsed.port}")

    return risks


def lexical_risk_factors(host: str) -> list:
    factors = []

    if contains_punycode(host):
        factors.append("Contains punycode")
    if has_excessive_digits(host):
        factors.append("Many digits in hostname")
    if has_long_hostname(host):
        factors.append("Long hostname")
    if has_many_hyphens(host):
        factors.append("Many hyphens in hostname")
    if count_subdomains(host) >= 3:
        factors.append("Many subdomains")
    if is_shortener_domain(host):
        factors.append("URL shortener domain")

    keyword_hits = check_suspicious_keywords(host)
    if keyword_hits:
        factors.append("Suspicious hostname keywords")

    brand_hits = looks_like_brand_impersonation(host)
    if brand_hits:
        factors.append("Possible brand impersonation")

    return factors


# =========================
# RISK SCORING
# =========================
def score_ip_target(result: dict):
    score = 0

    if result["ip_category"] == "Public":
        score += 15

    if result["reverse_dns"] == "Not Found":
        score += 15

    if result["ip_category"] in {"Reserved", "Unknown", "Invalid"}:
        score += 25

    if result["resolved_ip"] == result["input"] and result["ip_category"] == "Public":
        score += 5

    return score


def score_domain_target(result: dict):
    score = 0

    score += len(result["suspicious_keywords"]) * 8
    score += len(result["lexical_risks"]) * 6
    score += len(result["brand_impersonation_hits"]) * 12

    if result["suspicious_tld"]:
        score += 20

    if result["contains_punycode"]:
        score += 20

    if result["reverse_dns"] == "Not Found":
        score += 10

    if result["ip_category"] == "Public":
        score += 5

    if result["resolved_ip"] == "Resolution Failed":
        score += 20

    if result["subdomain_count"] >= 3:
        score += 8

    return score


def score_url_target(result: dict):
    score = 0

    score += len(result["suspicious_keywords"]) * 8
    score += len(result["lexical_risks"]) * 5
    score += len(result["path_risks"]) * 6
    score += len(result["scheme_risks"]) * 8
    score += len(result["brand_impersonation_hits"]) * 12

    if result["suspicious_tld"]:
        score += 20

    if result["contains_punycode"]:
        score += 20

    if result["reverse_dns"] == "Not Found":
        score += 10

    if result["resolved_ip"] == "Resolution Failed":
        score += 20

    if result["host_is_ip"]:
        score += 15

    if result["is_shortener"]:
        score += 15

    return score


def determine_risk_level(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


# =========================
# ANALYSIS
# =========================
def analyze_ip_target(target: str) -> dict:
    result = {
        "input": target,
        "input_type": "IP Address",
        "display_host": target,
        "resolved_ip": target,
        "reverse_dns": reverse_dns_lookup(target),
        "ip_category": get_ip_category(target),
        "suspicious_keywords": [],
        "suspicious_tld": False,
        "lexical_risks": [],
        "brand_impersonation_hits": [],
        "contains_punycode": False,
        "subdomain_count": 0,
        "host_is_ip": True,
        "is_shortener": False,
        "path_risks": [],
        "scheme_risks": [],
        "risk_score": 0,
        "risk_level": "Low",
        "geolocation": get_ip_geolocation(target)
    }

    result["risk_score"] = score_ip_target(result)
    result["risk_level"] = determine_risk_level(result["risk_score"])
    return result


def analyze_domain_target(target: str) -> dict:
    resolved_ip = resolve_domain(target)
    reverse_dns = reverse_dns_lookup(resolved_ip) if resolved_ip != "Resolution Failed" else "Not Found"

    result = {
        "input": target,
        "input_type": "Domain",
        "display_host": target,
        "resolved_ip": resolved_ip,
        "reverse_dns": reverse_dns,
        "ip_category": get_ip_category(resolved_ip) if resolved_ip != "Resolution Failed" else "Unknown",
        "suspicious_keywords": check_suspicious_keywords(target),
        "suspicious_tld": check_suspicious_tld(target),
        "lexical_risks": lexical_risk_factors(target),
        "brand_impersonation_hits": looks_like_brand_impersonation(target),
        "contains_punycode": contains_punycode(target),
        "subdomain_count": count_subdomains(target),
        "host_is_ip": False,
        "is_shortener": is_shortener_domain(target),
        "path_risks": [],
        "scheme_risks": [],
        "risk_score": 0,
        "risk_level": "Low",
        "geolocation": get_ip_geolocation(resolved_ip) if resolved_ip != "Resolution Failed" else {
            "country": "-", "region": "-", "city": "-", "zip": "-", "timezone": "-", "isp": "-", "lat": "-", "lon": "-", "note": "No IP"
        }
    }

    result["risk_score"] = score_domain_target(result)
    result["risk_level"] = determine_risk_level(result["risk_score"])
    return result


def analyze_url_target(target: str) -> dict:
    parsed = urlparse(target)
    host = parsed.hostname or ""
    host = host.strip().lower()

    if is_ip_address(host):
        resolved_ip = host
        reverse_dns = reverse_dns_lookup(host)
        ip_category = get_ip_category(host)
        host_is_ip = True
    else:
        resolved_ip = resolve_domain(host)
        reverse_dns = reverse_dns_lookup(resolved_ip) if resolved_ip != "Resolution Failed" else "Not Found"
        ip_category = get_ip_category(resolved_ip) if resolved_ip != "Resolution Failed" else "Unknown"
        host_is_ip = False

    decoded_path = unquote(parsed.path or "")
    decoded_query = unquote(parsed.query or "")

    combined_text = f"{host} {decoded_path} {decoded_query}"

    result = {
        "input": target,
        "input_type": "URL",
        "display_host": host,
        "resolved_ip": resolved_ip,
        "reverse_dns": reverse_dns,
        "ip_category": ip_category,
        "suspicious_keywords": check_suspicious_keywords(combined_text),
        "suspicious_tld": check_suspicious_tld(host),
        "lexical_risks": lexical_risk_factors(host),
        "brand_impersonation_hits": looks_like_brand_impersonation(host),
        "contains_punycode": contains_punycode(host),
        "subdomain_count": count_subdomains(host) if host and not host_is_ip else 0,
        "host_is_ip": host_is_ip,
        "is_shortener": is_shortener_domain(host),
        "path_risks": path_risk_factors(decoded_path, decoded_query),
        "scheme_risks": detect_url_scheme_risk(parsed),
        "risk_score": 0,
        "risk_level": "Low",
        "geolocation": get_ip_geolocation(resolved_ip) if resolved_ip != "Resolution Failed" else {
            "country": "-", "region": "-", "city": "-", "zip": "-", "timezone": "-", "isp": "-", "lat": "-", "lon": "-", "note": "No IP"
        }
    }

    result["risk_score"] = score_url_target(result)
    result["risk_level"] = determine_risk_level(result["risk_score"])
    return result


def analyze_target(target: str) -> dict:
    target = normalize_input(target)

    if is_ip_address(target):
        return analyze_ip_target(target)

    if is_url(target):
        return analyze_url_target(target)

    if is_domain(target):
        return analyze_domain_target(target)

    return {
        "input": target,
        "input_type": "Invalid",
        "display_host": "-",
        "resolved_ip": "-",
        "reverse_dns": "-",
        "ip_category": "Invalid",
        "suspicious_keywords": [],
        "suspicious_tld": False,
        "lexical_risks": [],
        "brand_impersonation_hits": [],
        "contains_punycode": False,
        "subdomain_count": 0,
        "host_is_ip": False,
        "is_shortener": False,
        "path_risks": [],
        "scheme_risks": [],
        "risk_score": 100,
        "risk_level": "High",
        "geolocation": {
            "country": "-", "region": "-", "city": "-", "zip": "-", "timezone": "-", "isp": "-", "lat": "-", "lon": "-", "note": "Invalid Input"
        }
    }


# =========================
# RENDERING
# =========================
def render_summary_table(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Threat Intelligence Summary:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    risk_color = Colors.GREEN
    if result["risk_level"] == "Medium":
        risk_color = Colors.YELLOW
    elif result["risk_level"] == "High":
        risk_color = Colors.RED

    rows = [
        ("Input Type", result["input_type"], Colors.WHITE),
        ("Display Host", str(result["display_host"])[:15], Colors.CYAN),
        ("Resolved IP", str(result["resolved_ip"])[:15], Colors.GREEN),
        ("Reverse DNS", str(result["reverse_dns"])[:15], Colors.YELLOW),
        ("IP Category", result["ip_category"], Colors.CYAN),
        ("Risk Score", str(result["risk_score"]), risk_color),
        ("Risk Level", result["risk_level"], risk_color),
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


def render_geo_table(result: dict):
    geo = result["geolocation"]

    print("\n" + Colors.MAGENTA + Colors.BOLD + "IP Geolocation / Network Context:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Checking':^25}|{'Status':^28}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Country", geo["country"]),
        ("Region", geo["region"]),
        ("City", geo["city"]),
        ("ZIP", geo["zip"]),
        ("Timezone", geo["timezone"]),
        ("ISP / ASN Context", geo["isp"]),
        ("Latitude", geo["lat"]),
        ("Longitude", geo["lon"]),
        ("GeoIP Note", geo["note"]),
    ]

    for label, value in rows:
        value_text = str(value)[:28]
        print(
            Colors.WHITE + "|" +
            f"{label:<25}" +
            "|" +
            Colors.YELLOW + f"{value_text:^28}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


def render_signal_table(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Suspicion Signals:" + Colors.RESET)

    border = "+------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'Signal':^38}|{'Status':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    rows = [
        ("Suspicious TLD", "YES" if result["suspicious_tld"] else "NO", Colors.RED if result["suspicious_tld"] else Colors.GREEN),
        ("Contains Punycode", "YES" if result["contains_punycode"] else "NO", Colors.RED if result["contains_punycode"] else Colors.GREEN),
        ("Host Is Direct IP", "YES" if result["host_is_ip"] else "NO", Colors.YELLOW if result["host_is_ip"] else Colors.GREEN),
        ("URL Shortener", "YES" if result["is_shortener"] else "NO", Colors.YELLOW if result["is_shortener"] else Colors.GREEN),
        ("Subdomain Count", str(result["subdomain_count"]), Colors.CYAN),
        ("Keyword Hits", str(len(result["suspicious_keywords"])), Colors.YELLOW if result["suspicious_keywords"] else Colors.GREEN),
        ("Lexical Risks", str(len(result["lexical_risks"])), Colors.YELLOW if result["lexical_risks"] else Colors.GREEN),
        ("Brand Impersonation Hints", str(len(result["brand_impersonation_hits"])), Colors.RED if result["brand_impersonation_hits"] else Colors.GREEN),
        ("Path Risks", str(len(result["path_risks"])), Colors.YELLOW if result["path_risks"] else Colors.GREEN),
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


def render_list_table(title: str, items: list, color: str, empty_text: str):
    print("\n" + color + Colors.BOLD + title + ":" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Value':^46}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not items:
        print(
            Colors.WHITE + "|" +
            f"{'-':^6}" +
            "|" +
            Colors.GREEN + f"{empty_text:^46}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )
    else:
        for idx, item in enumerate(items, start=1):
            text = str(item)[:46]
            print(
                Colors.WHITE + "|" +
                f"{str(idx):^6}" +
                "|" +
                color + f"{text:<46}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_batch_results_table(results: list):
    print("\n" + Colors.CYAN + Colors.BOLD + "Batch IOC Triage Results:" + Colors.RESET)

    border = "+-----------------------------------------------------------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^5}|{'Type':^12}|{'Input':^42}|{'Risk Score':^12}|{'Risk':^10}|{'Resolved IP':^15}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    if not results:
        print(Colors.WHITE + f"|{'-':^5}|{'-':^12}|{'None':^42}|{'0':^12}|{'-':^10}|{'-':^15}|" + Colors.RESET)
    else:
        for idx, item in enumerate(results, start=1):
            risk_color = Colors.GREEN
            if item["risk_level"] == "Medium":
                risk_color = Colors.YELLOW
            elif item["risk_level"] == "High":
                risk_color = Colors.RED

            print(
                Colors.WHITE + "|" +
                f"{idx:^5}" +
                "|" +
                Colors.CYAN + f"{item['input_type'][:12]:^12}" +
                Colors.WHITE + "|" +
                f"{item['input'][:42]:<42}" +
                "|" +
                risk_color + f"{str(item['risk_score']):^12}" +
                Colors.WHITE + "|" +
                risk_color + f"{item['risk_level']:^10}" +
                Colors.WHITE + "|" +
                Colors.YELLOW + f"{str(item['resolved_ip'])[:15]:^15}" +
                Colors.WHITE + "|" +
                Colors.RESET
            )

    print(Colors.CYAN + border + Colors.RESET)


def render_recommendations(result: dict):
    print("\n" + Colors.CYAN + Colors.BOLD + "Investigation Recommendations:" + Colors.RESET)

    border = "+-----------------------------------------------------+"
    print(Colors.CYAN + border + Colors.RESET)
    print(Colors.WHITE + f"|{'#':^6}|{'Recommendation':^46}|" + Colors.RESET)
    print(Colors.CYAN + border + Colors.RESET)

    recommendations = []

    if result["input_type"] == "Invalid":
        recommendations.append("Verify the IOC format before analysis.")
    else:
        if result["risk_level"] == "High":
            recommendations.append("Investigate this IOC immediately.")
            recommendations.append("Check firewall / proxy / DNS logs for hits.")
            recommendations.append("Correlate with endpoint alerts or auth logs.")
        elif result["risk_level"] == "Medium":
            recommendations.append("Review DNS, HTTP, and access patterns.")
            recommendations.append("Search for related activity across logs.")
        else:
            recommendations.append("Monitor for future suspicious activity.")

        if result["reverse_dns"] == "Not Found":
            recommendations.append("Perform additional reputation lookup.")
        if result["suspicious_tld"]:
            recommendations.append("Inspect registrar, age, and registration data.")
        if result["brand_impersonation_hits"]:
            recommendations.append("Review for phishing or impersonation use.")
        if result["contains_punycode"]:
            recommendations.append("Check for IDN or lookalike domain abuse.")
        if result["is_shortener"]:
            recommendations.append("Expand the short URL before trusting it.")
        if result["host_is_ip"]:
            recommendations.append("Direct-IP URLs often deserve scrutiny.")

    deduped = []
    for item in recommendations:
        if item not in deduped:
            deduped.append(item)

    if not deduped:
        deduped.append("No immediate action required.")

    for idx, item in enumerate(deduped[:8], start=1):
        text = item[:46]
        print(
            Colors.WHITE + "|" +
            f"{str(idx):^6}" +
            "|" +
            Colors.YELLOW + f"{text:<46}" +
            Colors.WHITE + "|" +
            Colors.RESET
        )

    print(Colors.CYAN + border + Colors.RESET)


# =========================
# USER WORKFLOWS
# =========================
def single_analysis_workflow():
    target = ask_input("Enter : | IP Address | Domain | URL | : ").strip()

    if not target:
        print_message(Colors.RED + "[!] No Input Provided !!!")
        sys.exit(1)

    print()
    print_message(Colors.YELLOW + "[-] Analyzing Target ...\n")

    result = analyze_target(target)

    render_summary_table(result)
    render_geo_table(result)
    render_signal_table(result)
    render_list_table("Suspicious Keyword Hits", result["suspicious_keywords"], Colors.YELLOW, "None Found")
    render_list_table("Lexical Risk Factors", result["lexical_risks"], Colors.MAGENTA, "None Found")
    render_list_table("Brand Impersonation Hints", result["brand_impersonation_hits"], Colors.RED, "None Found")
    render_list_table("URL Path / Query Risks", result["path_risks"], Colors.CYAN, "Not Applicable / None")
    render_list_table("Transport / Port Risks", result["scheme_risks"], Colors.YELLOW, "Not Applicable / None")
    render_recommendations(result)


def batch_analysis_workflow():
    print_message(Colors.BLUE + "[i] Enter Multiple IOCs Separated by Commas : ")
    print("                                           ")
    raw_text = ask_input("Enter IOC List: ").strip()

    if not raw_text:
        print_message(Colors.RED + "[!] No input provided.")
        sys.exit(1)

    targets = [item.strip() for item in raw_text.split(",") if item.strip()]

    print()
    print_message(Colors.YELLOW + "[-] Running Batch IOC Analysis ...\n")

    results = [analyze_target(target) for target in targets]
    results.sort(key=lambda x: x["risk_score"], reverse=True)

    render_batch_results_table(results)

    if results:
        print_message(Colors.YELLOW + "\n[-] Showing Detailed View for Highest-Risk IOC ...")
        top_result = results[0]
        render_summary_table(top_result)
        render_signal_table(top_result)
        render_recommendations(top_result)


# =========================
# MAIN
# =========================
def main():
    print_banner()

    print_message(Colors.BLUE + "[i] Mode        : IOC / Domain / URL Triage")
    print_message(Colors.BLUE + "[i] Input Type  : IP / Domain / URL")
    print_message(Colors.BLUE + "[i] Detection   : Heuristic Risk Scoring + GeoIP + Lexical Analysis")
    print_message(Colors.BLUE + "[i] Features    : Batch IOC Mode + Lookalike Signals + URL Risk Checks\n")

    try:
        print(Colors.CYAN + "Choose an Option:" + Colors.RESET)
        print(Colors.WHITE + "1. Analyze Single IOC" + Colors.RESET)
        print(Colors.WHITE + "2. Batch IOC Triage" + Colors.RESET)
        print(Colors.WHITE + "3. Exit\n" + Colors.RESET)

        choice = ask_input("Enter Choice [ 1 / 2 / 3 ] : ").strip()
        print("                                        ")

        if choice == "1":
            single_analysis_workflow()
        elif choice == "2":
            batch_analysis_workflow()
        elif choice == "3":
            print_message(Colors.YELLOW + "[-] Exiting.")
            sys.exit(0)
        else:
            print_message(Colors.RED + "[!] Invalid choice.")
            sys.exit(1)

    except KeyboardInterrupt:
        print_message("\n" + Colors.RED + "[!] Analysis interrupted by user.")
        sys.exit(0)
    except socket.gaierror as exc:
        print_message(Colors.RED + f"[!] DNS resolution error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print_message(Colors.RED + f"[!] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    time.sleep(60)
