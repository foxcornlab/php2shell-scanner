#!/usr/bin/env python3
"""`php2shell` scanner: detection-only triage for `PHP2Shell`.

`CVE-2026-109618` (OOM corruption via crafted multipart uploads, `mod_php`
highest risk) and `CVE-2026-109619` (stale global state use-after-free via
session upload-progress, `mod_php` and `PHP-FPM`).

This tool NEVER sends exploit traffic. It sends one plain `GET` request to a
target's root page and reads the headers and body the server already returns.
No `POST`, no multipart bodies, no upload-progress fields, no payloads of any
kind. Version detection is the honest angle: if the version is in the fixed
matrix, the target is clean; if it is not, the target needs patching.

Modes:
  --target URL   remote fingerprint: headers, SAPI hints, phpinfo exposure
  --local        local audit: `php -v` plus optional `--php-ini` check

Exit codes: 0 = clean or unknown, 2 = vulnerable version found,
1 = scan error (unreachable target, missing php binary, bad args).
"""

import argparse
import json
import re
import subprocess
import sys
import urllib.request
import urllib.error

TOOL_NAME = "php2shell-scanner"
TOOL_VERSION = "1.0.0"
USER_AGENT = "php2shell-scanner/1.0 (detection-only)"

# Fixed versions shipped 2026-10-21. Branch -> first fixed release.
FIXED_MATRIX = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

CVE_109618 = "CVE-2026-109618"
CVE_109619 = "CVE-2026-109619"

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
X_POWERED_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.IGNORECASE)
PHPINFO_MARKERS = ("phpinfo()", "PHP Version", "PHP Credits")


def parse_version(text):
    """Parse `major.minor.patch` out of a string. Returns a tuple or None."""
    if not text:
        return None
    m = VERSION_RE.search(text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def version_string(ver):
    return ".".join(str(x) for x in ver)


def grade_version(ver):
    """Grade a PHP version against the fixed matrix.

    Returns (verdict, detail) where verdict is one of:
    CLEAN, VULNERABLE, VULNERABLE_EOL, NEWER_BRANCH, UNKNOWN.
    """
    if ver is None:
        return ("UNKNOWN", "no PHP version disclosed")
    branch = (ver[0], ver[1])
    if branch in FIXED_MATRIX:
        fixed = FIXED_MATRIX[branch]
        if ver >= fixed:
            return ("CLEAN", "at or above fixed %s" % version_string(fixed))
        return ("VULNERABLE", "below fixed %s" % version_string(fixed))
    if branch < (8, 2):
        return ("VULNERABLE_EOL",
                "branch %d.%d has no official fix; upgrade to a supported "
                "branch (distro backports may exist)" % branch)
    # Branch newer than 8.5 postdates the Oct 2026 advisory matrix.
    return ("NEWER_BRANCH",
            "branch %d.%d postdates the advisory matrix; confirm against "
            "the vendor advisory" % branch)


def detect_sapi(server_header, powered_by):
    """Best-effort SAPI hint from response headers. Heuristic, not proof.

    Returns one of: mod_php, fpm, likely-fpm, unknown.
    """
    server = (server_header or "").lower()
    if "mod_php" in server:
        return "mod_php"
    if "apache" in server and "php/" in server:
        # PHP loaded as an Apache module advertises itself in Server.
        return "mod_php"
    if "fpm" in server:
        return "fpm"
    if "nginx" in server and powered_by:
        # nginx never embeds PHP; PHP behind nginx is almost always FPM.
        return "likely-fpm"
    return "unknown"


def severity_for(verdict, sapi):
    """Map a version verdict + SAPI hint to a severity."""
    if verdict in ("VULNERABLE", "VULNERABLE_EOL"):
        if sapi == "mod_php":
            return "CRITICAL"
        return "HIGH"
    if verdict == "CLEAN":
        return "CLEAN"
    if verdict == "NEWER_BRANCH":
        return "CLEAN"
    return "UNKNOWN"


def analyze_headers(headers, body=b""):
    """Analyse response headers (and root body) for PHP exposure.

    headers: dict-like with .get(); body: raw response bytes.
    Returns a dict with version, sapi, verdict, severity, notes.
    """
    powered_by = headers.get("X-Powered-By", "")
    server = headers.get("Server", "")
    ver = parse_version(powered_by)
    if ver is None:
        # Fall back only to an explicit PHP token in the Server header
        # (e.g. "Apache/2.4.62 (Unix) PHP/8.2.34"). Never take the web
        # server's own version number as the PHP version.
        m = X_POWERED_RE.search(server)
        if m:
            ver = parse_version(m.group(1))
    sapi = detect_sapi(server, powered_by)
    verdict, detail = grade_version(ver)
    notes = []
    if powered_by:
        notes.append("X-Powered-By: %s" % powered_by)
    if server:
        notes.append("Server: %s" % server)
    body_text = body.decode("utf-8", errors="ignore") if body else ""
    if any(m in body_text for m in PHPINFO_MARKERS):
        notes.append("phpinfo output exposed in root response body "
                     "(information disclosure; confirms PHP stack)")
    if sapi == "mod_php":
        notes.append("SAPI hint: mod_php (highest-risk config for %s)"
                     % CVE_109618)
    elif sapi in ("fpm", "likely-fpm"):
        notes.append("SAPI hint: %s (session upload-progress path for %s "
                     "is on by default)" % (sapi, CVE_109619))
    else:
        notes.append("SAPI unknown from headers; version alone drives "
                     "the verdict")
    if verdict == "VULNERABLE_EOL":
        notes.append("PHP 8.1 and older get no official fix; minimal source "
                     "backports exist for 7.4/8.0/8.1, distro backports vary")
    return {
        "version": version_string(ver) if ver else None,
        "sapi": sapi,
        "verdict": verdict,
        "severity": severity_for(verdict, sapi),
        "detail": detail,
        "notes": notes,
    }


def scan_target(url, timeout=15):
    """One plain GET to the target root. No payloads, no POST, no params."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            body = resp.read(65536)
            status = resp.status
    except urllib.error.HTTPError as e:
        # Even an error page can carry X-Powered-By / Server headers.
        headers = {k: v for k, v in e.headers.items()}
        try:
            body = e.read(65536)
        except Exception:
            body = b""
        status = e.code
    result = analyze_headers(headers, body)
    result["target"] = url
    result["http_status"] = status
    return result


def scan_local(php_ini_path=None):
    """Local audit: `php -v` version plus optional php.ini check."""
    try:
        out = subprocess.run(["php", "-v"], capture_output=True, text=True,
                             timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"error": "php binary not found or timed out"}
    ver = parse_version(out.stdout or "")
    verdict, detail = grade_version(ver)
    result = {
        "version": version_string(ver) if ver else None,
        "verdict": verdict,
        "severity": severity_for(verdict, "unknown"),
        "detail": detail,
        "notes": ["local php -v output parsed; no SAPI signal locally"],
    }
    if php_ini_path:
        result["php_ini"] = check_php_ini(php_ini_path)
    return result


def check_php_ini(path):
    """Parse a php.ini for the 109619 session upload-progress mitigation.

    Disabling upload-progress is a PARTIAL mitigation for the session path
    only. It does not fix either CVE. Updating is the only complete fix.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        return {"error": "cannot read php.ini: %s" % e}
    settings = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            settings[key.strip().lower()] = val.strip().strip("\"'")
    up = settings.get("session.upload_progress.enabled")
    up_off = up is not None and up.lower() in ("0", "off", "false", "no")
    return {
        "session.upload_progress.enabled": up,
        "upload_progress_disabled": up_off,
        "mitigation_note": (
            "upload-progress disabled: partial mitigation for the %s "
            "session path only, restart workers after changing; "
            "updating is the only complete fix" % CVE_109619
            if up_off else
            "upload-progress enabled or unset (default on): the %s "
            "session path is reachable; patch, do not rely on config"
            % CVE_109619),
        "memory_limit": settings.get("memory_limit"),
    }


def render_report(result):
    """Human-readable triage report."""
    lines = []
    lines.append("=" * 60)
    lines.append("php2shell triage: %s / %s" % (CVE_109618, CVE_109619))
    lines.append("=" * 60)
    if "target" in result:
        lines.append("target      : %s (HTTP %s)"
                     % (result["target"], result.get("http_status")))
    if "error" in result:
        lines.append("ERROR       : %s" % result["error"])
        return "\n".join(lines)
    lines.append("php version : %s" % (result["version"] or "not disclosed"))
    if "sapi" in result:
        lines.append("sapi hint   : %s" % result["sapi"])
    lines.append("verdict     : %s (%s)" % (result["verdict"], result["detail"]))
    lines.append("severity    : %s" % result["severity"])
    if result["notes"]:
        lines.append("notes       :")
        for n in result["notes"]:
            lines.append("  - %s" % n)
    if "php_ini" in result:
        ini = result["php_ini"]
        lines.append("php.ini     :")
        if "error" in ini:
            lines.append("  - %s" % ini["error"])
        else:
            lines.append("  - session.upload_progress.enabled = %s"
                         % ini.get("session.upload_progress.enabled"))
            lines.append("  - %s" % ini["mitigation_note"])
            if ini.get("memory_limit"):
                lines.append("  - memory_limit = %s" % ini["memory_limit"])
    if result["severity"] in ("CRITICAL", "HIGH"):
        lines.append("action      : UPDATE PHP to 8.5.12 / 8.4.27 / 8.3.36 / "
                     "8.2.35 now; updating is the only complete fix")
    elif result["severity"] == "CLEAN":
        lines.append("action      : none; version is at or above the fix")
    else:
        lines.append("action      : version not disclosed; confirm via "
                     "local `php -v` or server config")
    lines.append("detection-only: no exploit payloads were sent")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Detection-only triage scanner for PHP2Shell "
                    "(%s / %s). Sends no exploit payloads; version "
                    "fingerprinting only." % (CVE_109618, CVE_109619))
    p.add_argument("--target", metavar="URL",
                   help="remote target to fingerprint (one plain GET)")
    p.add_argument("--local", action="store_true",
                   help="audit the local PHP install via `php -v`")
    p.add_argument("--php-ini", metavar="PATH",
                   help="php.ini to check (use with --local)")
    p.add_argument("--json", action="store_true",
                   help="print machine-readable JSON instead of the report")
    p.add_argument("--timeout", type=int, default=15,
                   help="HTTP timeout in seconds (default 15)")
    args = p.parse_args(argv)

    if args.target and args.local:
        p.error("--target and --local are mutually exclusive")
    if not args.target and not args.local:
        p.error("one of --target or --local is required")
    if args.php_ini and not args.local:
        p.error("--php-ini only makes sense with --local")

    if args.target:
        try:
            result = scan_target(args.target, timeout=args.timeout)
        except Exception as e:
            print("ERROR: target unreachable: %s" % e, file=sys.stderr)
            return 1
    else:
        result = scan_local(args.php_ini)
        if "error" in result:
            print("ERROR: %s" % result["error"], file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_report(result))
    return 2 if result.get("severity") in ("CRITICAL", "HIGH") else 0


if __name__ == "__main__":
    sys.exit(main())
