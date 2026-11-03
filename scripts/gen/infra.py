"""Network address plan. Benign SaaS lookups use plausible public addresses; employee home
broadband uses TEST-NET-1 (192.0.2.0/24). Attacker infrastructure is restricted to the two
other documentation ranges and .example domains, and safety.py enforces that."""

import ipaddress

TENANT = "contoso"
INTERNAL_DOMAIN = "corp.internal"

BAD_NETS = (ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("198.51.100.0/24"))
BAD_DOMAIN_SUFFIX = ".example"
HOME_NET = ipaddress.ip_network("192.0.2.0/24")

# domain -> resolved address
BENIGN_DOMAINS: dict[str, str] = {
    "outlook.office365.com": "52.97.146.162",
    "login.microsoftonline.com": "20.190.159.68",
    "graph.microsoft.com": "20.190.152.18",
    "teams.microsoft.com": "52.113.194.132",
    f"{TENANT}.sharepoint.com": "13.107.136.10",
    f"{TENANT}-my.sharepoint.com": "13.107.138.10",
    "settings-win.data.microsoft.com": "20.42.65.85",
    "definitionupdates.microsoft.com": "13.107.4.50",
    "fe3cr.delivery.mp.microsoft.com": "20.12.23.50",
    "www.office.com": "13.107.6.156",
    "www.google.com": "142.250.180.4",
    "update.googleapis.com": "142.250.187.227",
    "www.bbc.co.uk": "151.101.0.81",
    "www.gov.uk": "151.101.64.144",
    "www.linkedin.com": "13.107.42.14",
    "github.com": "140.82.121.4",
    "pypi.org": "151.101.128.223",
    "files.pythonhosted.org": "151.101.192.223",
    "stackoverflow.com": "104.18.32.7",
    "docs.python.org": "151.101.0.223",
    "login.salesforce.com": "136.146.42.10",
    "app.hubspot.com": "104.18.240.100",
    "go.xero.com": "52.31.84.203",
    "www.hmrc.gov.uk": "151.101.192.144",
    "acrobat.adobe.com": "23.214.107.94",
    "zoom.us": "170.114.52.2",
}

BENIGN_IPS = frozenset(BENIGN_DOMAINS.values())


def is_bad_ip(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in net for net in BAD_NETS)


def is_bad_domain(domain: str) -> bool:
    return domain.lower().endswith(BAD_DOMAIN_SUFFIX)
