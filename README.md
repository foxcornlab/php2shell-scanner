# `php2shell-scanner`

Detection-only triage scanner for `PHP2Shell`, the unauthenticated RCE pair in `PHP` core. It fingerprints a target's `PHP` version and `SAPI`, grades it against the fixed matrix, and tells you whether to patch. It never exploits anything.

## `The flaws`

| `CVE` | `Bug` | `Highest-risk config` |
|---|---|---|
| `CVE-2026-109618` | `RCE` via `OOM` corruption in crafted multipart handling | `Apache mod_php`, triggerable before app code runs |
| `CVE-2026-109619` | `RCE` via stale global state use-after-free | `PHP-FPM` via session upload-progress (on by default), plus `mod_php` |

Both are rated `CVSS v4.0 9.2` by the `PHP` project and `CVSS 3.1 9.8` on `NVD`. Every `PHP` install serving web requests is in scope: `mod_php`, `PHP-FPM`, `php-cgi`, `FrankenPHP`, `LiteSpeed`, back to `PHP 5.4`.

## `Fixed versions`

| `Branch` | `First fixed release` |
|---|---|
| `8.5` | `8.5.12` |
| `8.4` | `8.4.27` |
| `8.3` | `8.3.36` |
| `8.2` | `8.2.35` |

`PHP 8.1` and older get no official fix. Minimal source backports exist for `7.4`/`8.0`/`8.1`, and distro backports vary. Updating is the only complete fix.

## `What it checks`

- `PHP` version from `X-Powered-By` and `Server` headers
- `SAPI` hints: `mod_php` vs `PHP-FPM` indicators (heuristic, labelled as such)
- `phpinfo` exposure in the root response body
- Local mode: `php -v` version plus `php.ini` audit (`session.upload_progress.enabled`, `memory_limit`)

## `What it never does`

No `POST` requests. No multipart bodies. No upload-progress fields. No payloads of any kind. One plain `GET` to the target root, reading headers the server already returns. Version detection is the honest angle.

## `Grading`

| `Finding` | `Severity` |
|---|---|
| Vulnerable version + `mod_php` | `CRITICAL` |
| Vulnerable version + `PHP-FPM` (or unknown `SAPI`) | `HIGH` |
| `EOL` branch (`8.1` and older, no official fix) | `HIGH` (`CRITICAL` on `mod_php`) |
| Fixed version | `CLEAN` |
| No version disclosed | `UNKNOWN`, not vulnerable |

## `Usage`

```bash
# Remote fingerprint (one plain GET, no payloads)
python3 php2shell.py --target https://example.com/

# Machine-readable output
python3 php2shell.py --target https://example.com/ --json

# Local audit
python3 php2shell.py --local
python3 php2shell.py --local --php-ini /etc/php/8.4/fpm/php.ini
```

Exit codes: `0` = clean or unknown, `2` = vulnerable version found, `1` = scan error.

## `Partial mitigations (not fixes)`

Disabling `session.upload_progress.enabled` plus restarting workers is a partial mitigation for the `CVE-2026-109619` session path only. It does not fix either `CVE`. For `PHP 8.5` installs that cannot update, the advisory also suggests `fatal_error_backtraces=0`. Treat both as stopgaps. Update.

## `Honest caveats`

- Early public `PoC` material mostly failed against default `PHP`, and `Sansec` walked back mass-exploitation claims on `2026-10-22`.
- By `2026-10-24`, honeypot command executions were reported, so exploitation attempts are real and ongoing.
- `VulnCheck` has demonstrated a private `ASLR`-bypassing exploit (memory-leak chain to `RCE` on `8.4.26`). Reliable exploitation is proven possible, just not public.
- No named production compromise is publicly confirmed. This scanner does version detection, not exploit verification.

## `References`

- `PHP` advisory: `GHSA-w8hw-w9fx-j79w` (`109618`), `GHSA-6wmf-4rv5-p3rp` (`109619`)
- `Rapid7` analysis of both `CVE`s
- `watchTowr`, `Sansec`, `Tenable`, `SOCRadar` write-ups

## `Thanks to`

- The `PHP` security team for the advisory and fixed releases
- `watchTowr`, `Wiz`, `Calif` and the researchers who found and documented the flaws
- Everyone running honeypots and publishing exploitation telemetry

## `Disclaimer`

Built for defensive triage and authorized testing only. Scan only systems you own or are authorized to test. The authors are not responsible for misuse.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
