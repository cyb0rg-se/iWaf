# DemoShop Pro — PhoenixWAF test target

A deliberately **vulnerable** multi-page PHP shop (no database — state in `$_SESSION`
and JSON files) used to validate PhoenixWAF end-to-end. **Isolated from the project
root**: the runner only *copies* `../waf.php` into `common.inc.php` here; it never
writes to the real WAF source. Delete this whole folder anytime.

## Run

```bash
bash run_tests.sh          # functional suite: boots php -S + WAF (front controller), 113 checks
bash run_install_test.sh   # REAL deployment: runs `php waf.php --install` on a copy, verifies the
                           # hidden .dir + physical injection + mounts + honeypots, drives traffic
```

Requires `php` and `curl` on PATH.

- `run_tests.sh` loads the WAF via `router.php` (front controller) so it runs for **every**
  request path incl. non-existent scanner paths — convenient for exhaustive functional testing.
- `run_install_test.sh` uses the **actual installer** (`--install`): the WAF is loaded by the
  physical `@include_once` injected into each PHP file, exactly as in production. It validates the
  stealth topology (`.<rand8>/common.inc.php`, `.user.ini`, `.htaccess` ForceType, `flag`/`flag.txt`
  honeypots) and confirms the injection-loaded WAF blocks attacks and scrubs flags.

## What it exercises (113 checks)

- **A. Normal business journeys** (must pass, zero WAF impact): register/login (session),
  catalog search + category filter + sort + pagination, product detail, add-to-cart,
  checkout, post review, edit profile (unicode/apostrophe), contact, password reset,
  file view, image upload (PNG), link preview, catalog export, template preview, JSON
  API (ping/search/token-auth order), AJAX suggest, admin dashboard, static assets,
  plus false-positive guards (prose with `and`/`order by`/`between`, hex colors, paths).
- **B. WAF panel UI**: login page, authenticated render, nav tabs (概览/检测规则/攻击日志),
  防护强度 selector, stat cards, rule badges, AJAX poll endpoint, wrong-password handling.
- **C. Attacks across every injection point** (must block): SQLi/XSS/LFI/RCE/SSRF/SSTI/
  NoSQL/XXE/deser/upload/CRLF via GET, POST, JSON, Cookie, and HTTP headers
  (User-Agent, X-Forwarded-For, Referer); plus scanner honeypot paths.
- **D. Bypass/evasion variants** (must block): double URL-encoding, MySQL version comments,
  case+whitespace, quote/backslash breaking, XSS slash/quote separators, `java\tscript:`,
  SSRF decimal/octal/IPv6/userinfo, base64(url) webshells, JWT alg:none, overlong UTF-8, JNDI.
- **E. Flag leak** (L2 response hook must scrub): plain/base64/hex/reversed/URL/JSON/HTML.

## Endpoints

`index catalog product cart checkout auth account admin review contact files fetch
export render reset api suggest flag` + `lib/common.php`, `pages/*`, `assets/*`.
