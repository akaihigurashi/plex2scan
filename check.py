"""
plex2scan.py - find Plex Media Servers affected by Plex2Shell, the chain of four
flaws (CVE-2026-96652, -96654, -96655, -96656) that lets attackers take over
Plex Media Server older than 1.43.3.10861 without logging in.
Part of shouldipanic.ch.

Plex2Shell has been exploited since 17 October 2026 (cryptominers, proxies) and
is on CISA's Known Exploited Vulnerabilities list. Every Plex Media Server older
than 1.43.3.10861 that can be reached from the internet is at risk.

For each IP/host it first runs a TCP connect scan of 20 common web ports plus
Plex's own port 32400 (-p all for all 65535). It then discovers the vhosts on
each IP (TLS certificates, redirects, reverse DNS, passive DNS, certificate
transparency, optionally your own name list) and checks every vhost on that IP.
On every open port it sends a normal GET request to "/" (following up to 5
redirects) and one GET request to "/identity", the public page where every Plex
Media Server tells its version. Nothing else is sent: no login, no exploit.
Only scan systems you are authorized to check.

Usage (results are printed to the terminal):
    python3 plex2scan.py 203.0.113.10               # 21 ports incl. 32400 + vhost discovery
    python3 plex2scan.py 198.51.100.0/24            # whole IP range
    python3 plex2scan.py 203.0.113.10:32400         # one Plex port only
    python3 plex2scan.py plex.example.ch            # a Plex behind a reverse proxy
    python3 plex2scan.py 203.0.113.10 -p all        # all 65535 TCP ports
    python3 plex2scan.py 203.0.113.0/24 --names domains.txt  # + your own hostnames
    python3 plex2scan.py 203.0.113.10 -d            # debug: requests, matches

Targets can be IPs, CIDR ranges, hostnames, URLs, or a file with one per line.

Status:
    VULNERABLE           Plex Media Server older than 1.43.3.10861
    POSSIBLY VULNERABLE  Plex Media Server found, version hidden
    PATCHED              Plex Media Server 1.43.3.10861 or newer
    NOT DETECTED         no Plex Media Server visible
    SNI ONLY       HTTPS server that only answers for its hostnames; see vhost results
    NOT HTTP       open port, but not a web server (shown with -a)
    ERROR          host not reachable / no open port (shown with -a)
"""
# check module for panic-core: everything specific to plex2scan.
# panic-core/bundle.py turns this file plus the engine into plex2scan.py.
from engine import *  # noqa: F401,F403  # bundle: strip

NAME = "plex2scan"
VERSION = "1.0.0"
DESCRIPTION = "Find Plex Media Servers affected by Plex2Shell (CVE-2026-96652 and three more)."
TARGETS = {"Plex Media Server"}
BUILTIN_LABEL = "Plex rules"
APPS_LABEL = "PRODUCT"
COLUMNS = ["target", "final_url", "http_status", "verdict", "plex_version", "product",
           "server", "evidence"]

BANNER = r"""
    ____  __    _______  _____  _____ __  __________    __
   / __ \/ /   / ____/ |/ /__ \/ ___// / / / ____/ /   / /
  / /_/ / /   / __/  |   /__/ /\__ \/ /_/ / __/ / /   / /
 / ____/ /___/ /___ /   |/ __/___/ / __  / /___/ /___/ /___
/_/   /_____/_____//_/|_/____/____/_/ /_/_____/_____/_____/
"""
BANNER_COLOR = "33"
BANNER_TAGS = ["Plex2Shell / CVE-2026-96652 + 3  ::  Plex Media Server takeover",
               "port scan incl. 32400  ::  vhosts  ::  /identity version check"]

PRODUCT = "Plex Media Server"
FIXED_VERSION = "1.43.3.10861"
PLEX_PORT = 32400
EXTRA_PORTS = str(PLEX_PORT)        # added to the 20 web ports of the port scan
WEB_EXTRA_PORTS = [PLEX_PORT]       # the web page also looks at this port

# (technology, where, regex). A capture group is the technology's version.
FINGERPRINTS = [
    (PRODUCT, "header", r"^x-plex-protocol:"),
    (PRODUCT, "header", r"^x-plex-content-(?:original|compressed)-length:"),
    (PRODUCT, "header", r"^access-control-expose-headers:[^\n]*\bx-plex-protocol\b"),
    (PRODUCT, "body", r"<title>\s*Plex\s*</title>"),
]
IMPLIES = {}

# Every Plex Media Server answers GET /identity without a login:
#   <MediaContainer size="0" claimed="1" machineIdentifier="..." version="1.43.2.10162-...">
VERSION_URLS = [
    (PRODUCT, "/identity",
     r'(?:<MediaContainer\b[^>]*?\bversion="|"MediaContainer"\s*:\s*\{.*?"version"\s*:\s*")'
     r"(\d+\.\d+\.\d+\.\d+)", None),
]


def builtin_count():              # every rule here is about Plex itself
    return len(FINGERPRINTS) + len(VERSION_URLS)


def version_tuple(v):
    return [int(x) for x in re.findall(r"\d+", v)[:4]]


def plex_status(version):
    """'vulnerable', 'patched' or '' (version unknown)."""
    if not version:
        return ""
    return "patched" if version_tuple(version) >= version_tuple(FIXED_VERSION) else "vulnerable"


def verdict(info):
    """(verdict, version, products) for the result row."""
    if PRODUCT not in info["techs"]:
        return "NOT DETECTED", "", []
    version = info["versions"].get(PRODUCT, "")
    state = plex_status(version)
    v = {"vulnerable": "VULNERABLE", "patched": "PATCHED"}.get(state, "POSSIBLY VULNERABLE")
    return v, version, [PRODUCT]


def count_key(v):
    return v


def verdict_style(row):
    """(rank, colour, status, reason) for the result list."""
    v, version = row[3], row[4]
    if v == "VULNERABLE":
        return 10, "red", v, f"Plex {version} < {FIXED_VERSION}"
    if v == "POSSIBLY VULNERABLE":
        return 20, "yellow", v, "Plex found, version hidden"
    if v == "PATCHED":
        return 40, "green", v, f"Plex {version}"
    if v == "NOT DETECTED":
        return 50, "plain", v, ""
    return None


EXAMPLES = f"""examples:
  plex2scan.py 203.0.113.10                        21 ports incl. {PLEX_PORT} + every vhost on the IP
  plex2scan.py 203.0.113.10:{PLEX_PORT}                  only Plex's own port
  plex2scan.py plex.example.ch                     a Plex behind a reverse proxy
  plex2scan.py 198.51.100.0/24 --names domains.txt a whole range + your own hostnames
  plex2scan.py 203.0.113.10 -p all -o out.csv      all 65535 ports, results also as CSV

status: VULNERABLE (older than {FIXED_VERSION}) - POSSIBLY VULNERABLE (Plex found, version
hidden) - PATCHED - NOT DETECTED
"""


# ---------------------------------------------------------------------------
# web page (web.py): assessment shown to visitors
# ---------------------------------------------------------------------------
CONSENT_VERSION = "2026-10-27.1"   # bump whenever the consent / rules text on the page changes

WHERE = {"version-url": "public /identity page"}

FIXED_TABLE = [   # (software, versions, note, applies-when-found)
    ("Plex Media Server", FIXED_VERSION, "or any newer release", True),
    ("Plex Media Server, Windows 32-bit", "", "no fix: last release is 1.42.2.10156, move to 64-bit",
     False),
]

STEPS = [
    "Update Plex Media Server to 1.43.3.10861 or newer. In Plex Web: Settings, General shows the "
    "server version; the update is under Settings, General or your system's package manager.",
    "If you don't watch from outside your home, turn off Remote Access and remove the port forwarding "
    "for 32400 on your router (also check UPnP).",
    "Restart Plex after updating and check the version again.",
]

COMPROMISE = {
    "intro": "Attackers have been using Plex2Shell since 17 October 2026. If your server was reachable "
             "from the internet with an older version, check it for these signs:",
    "signs": [
        "unfamiliar processes such as myawesomeproxy, mylovelyminer or x12345",
        "unknown .so or .dll files in Plex's Codecs folder",
        "connections to proxystream.st",
        "high CPU load while nothing is playing",
    ],
    "outro": "Updating doesn't remove an attacker who is already in. If you find any of these, "
             "rebuild the server, sign out all devices in your Plex account and change your password.",
}


def web_options(data):
    return {}


def web_result(host, ip, row, info, friendly_evidence):
    _, final, status, verdict_, version, products, server, evidence = row
    result = {"host": host, "ip": ip, "final_url": final, "http_status": status,
              "reachable": verdict_ not in ("ERROR", "SNI ONLY"), "verdict": verdict_,
              "server": server, "plex": False, "version": version, "evidence": [],
              "fixed": [], "steps": [], "compromise": None, "error": ""}
    if verdict_ == "ERROR":
        result["error"] = evidence
    if verdict_ == "SNI ONLY":
        result["error"] = "The server refused the HTTPS connection for this hostname."
    if not result["reachable"] or not info:
        result["status"] = {"level": "unknown", "title": "Not reachable",
                            "text": "We couldn't load this address."}
        return result

    result["plex"] = PRODUCT in info["techs"]
    result["evidence"] = friendly_evidence(", ".join(info["evidence"]))
    if result["plex"]:
        result["fixed"] = [{"software": s, "versions": v, "note": n, "found": f}
                           for s, v, n, f in FIXED_TABLE]
    if verdict_ == "VULNERABLE":
        st = {"level": "bad", "title": "Vulnerable",
              "text": f"This server runs Plex Media Server {version}. Plex2Shell is fixed in "
                      f"{FIXED_VERSION}. Attackers are using it right now: update today."}
        result["steps"], result["compromise"] = STEPS, COMPROMISE
    elif verdict_ == "PATCHED":
        st = {"level": "good", "title": "Patched",
              "text": f"This server runs Plex Media Server {version}, which includes the Plex2Shell fix."}
        result["steps"] = [STEPS[1]]
    elif verdict_ == "POSSIBLY VULNERABLE":
        st = {"level": "warn", "title": "Possibly vulnerable",
              "text": "We found a Plex Media Server, but it didn't tell us its version. Make sure it "
                      f"runs {FIXED_VERSION} or newer."}
        result["steps"], result["compromise"] = STEPS, COMPROMISE
    else:
        st = {"level": "good", "title": "No Plex found",
              "text": f"We found no Plex Media Server on this address, on the website or on port "
                      f"{PLEX_PORT}. A Plex that's only reachable at home can't be seen from outside, "
                      "and that's good."}
    result["status"] = st
    return result


def web_timeout_result(host, ip):
    return {"host": host, "ip": ip, "reachable": False, "verdict": "ERROR", "plex": False,
            "error": "The server took too long to respond.", "evidence": [], "fixed": [],
            "steps": [], "compromise": None,
            "status": {"level": "unknown", "title": "Not reachable",
                       "text": "The server took too long to respond."}}


def audit_fields(result):
    outcome = result.get("verdict", "ERROR").lower().replace(" ", "-")
    if outcome in ("error", "sni-only"):
        outcome = "unreachable"
    return {"outcome": outcome, "version": result.get("version", ""), "port": result.get("port", "")}
