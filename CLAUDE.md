# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 最高约束（AWD 单文件，必须遵守）

本项目为 **AWD 竞赛** 设计，靶机部署要极简、可拷即用。文件数量是硬限制，不是风格偏好：

- **所有 PHP（含面板 HTML/CSS/JS、安装器、配置默认值）只能写进 / 改 `waf.php` 这一个文件。**
- **所有 C 只能写进 / 改 `pwaf_ldpreload.c` 这一个文件。**
- **禁止** 为功能拆出新的 `.php` / `.c` / `.h` / `.js` / `.css` / 库目录 / 多文件模块。不要“重构成分文件更清晰”。
- 允许动的非产品文件仅限：`CLAUDE.md`、`README.md`、`LICENSE`、已有的 `test_web/` 测试靶场。不要再加第三份产品源码。

违反这条 = 做错了。改检测、面板、安装、LD_PRELOAD 钩子，都在这两个文件里完成。

## What this is

PhoenixWAF (aka iWAF) is a single-file PHP Web Application Firewall built for **AWD (Attack With Defense) CTF competitions**. Its job is to protect a target PHP site's flag while it runs *inside* that site, survive attacker attempts to remove it, and (optionally) automate counter-attacks (traffic replay, blind-spray "reap", auto flag submission). It is a purpose-built offensive/defensive CTF tool, not a general production WAF — comments and README are in Chinese.

The entire product is two files:
- `waf.php` — ~4200 lines, everything: request/response filtering, admin panel (HTML/CSS/JS inlined as PHP heredocs/echo), CLI installer, self-healing, counter-attack automation.
- `pwaf_ldpreload.c` — an `LD_PRELOAD` shared library that hooks libc syscalls to protect files and block dangerous command execution at the OS layer.

There is **no build system, package manager, test suite, or linter**. Don't look for `composer.json`, `Makefile`, or CI — they don't exist. "Running" this code means deploying it onto a target webroot.

## Commands

`waf.php` is dual-mode: run under the CLI SAPI it acts as an installer/manager; served over a web SAPI (via `auto_prepend_file`) it acts as the firewall. The dispatch is at `waf.php:63` (`if (PHP_SAPI === 'cli')`).

```bash
# Deploy the WAF onto a target webroot (creates hidden dir, injects into all PHP files,
# writes .user.ini + .htaccess mounts, compiles the .so, sets chattr +i locks)
php waf.php --install /var/www/html [--password PASS] [--key PANELKEY]

php waf.php --uninstall /var/www/html   # remove mounts, injected tags, hidden dir
php waf.php --status    /var/www/html   # show deployment status
php waf.php --baseline  /var/www/html   # rebuild the SHA256 integrity baseline
php waf.php --immortal  /var/www/html   # (re)deploy the inotifywait file watcher only
php waf.php --ldpreload /var/www/html   # compile + deploy the LD_PRELOAD .so only
```

Admin panel (after install): browse to any real PHP page on the target with `?waf_key=PANELKEY`, then log in with the admin password.

Compiling the LD_PRELOAD library standalone (normally the installer does this automatically; header comment in `pwaf_ldpreload.c` has cross-compile variants):
```bash
gcc -shared -fPIC -O2 -s -o waf.so pwaf_ldpreload.c -ldl
# Override baked-in paths at compile time:
gcc -shared -fPIC -O2 -s -DPWAF_LOG_PATH='"/path/.pwaf_log"' -DPWAF_WEBROOT='"/var/www/html"' -o waf.so pwaf_ldpreload.c -ldl
```

A minified (`php -w`, comments/whitespace stripped) distribution build lives in the repo's GitHub Releases — it is generated from `waf.php`, so **edit `waf.php`, never the minified release**.

## Runtime architecture (the request lifecycle)

The web entry point is `pwaf_run()` (`waf.php:624`), invoked from `waf.php:67` inside a global try/catch. Everything after here is defense layers L1–L10 (numbered in the file header at `waf.php:12`). Understanding the *order* matters because each stage can short-circuit the request:

1. **Superglobal snapshot** — `$_GET/$_POST/$_COOKIE/$_FILES/$_SERVER` are frozen into `$GLOBALS['_PWAF_*']` immediately so later attacker code can't repollute them. All subsequent logic reads the snapshot, not the live superglobals.
2. **Config load** — `pwaf_cfg()` returns a `&`-reference to a static config array loaded from `.pwaf.php` (a `<?php return [...]` file). If disabled, returns early.
3. **Panel check** — a valid `waf_key` (constant-time compared) hands off to `pwaf_panel()` and exits.
4. **L8 checker auto-whitelist** → **whitelist / checker** pass → **blacklist / L4 rate-limit** block → **L5 honeypot paths** (serve fake flag, optionally ban).
5. **L1 request filtering** — the core loop: `pwaf_inputs()` enumerates every input source, `pwaf_decode()` produces multiple decoded variants of each value (defeats encoding bypasses), and each variant is matched against `pwaf_patterns()` per enabled rule category, plus user-defined `custom_rules`. A hit calls `pwaf_block()` and returns.
6. **L2 response hook** — `ob_start()` + `register_shutdown_function` wrap output so flag leakage in the body *and in HTTP headers* is caught even across `exit()`/`die()`; leaked flags are replaced with same-length fakes and (if configured) auto-submitted.
7. **Periodic tasks** (throttled to every 5s via a timestamp file): **L9 self-heal** (restore core file from backup if deleted) and **L7 integrity check** (`pwaf_integrity_check` vs SHA256 baseline).

Key design invariants when editing this flow:
- **Never let the WAF break the host app.** L10 is the whole philosophy: any exception is swallowed and the request passes. Blocking is stealthy by default (`pwaf_chameleon_response` fakes a plausible 200 with a randomized delay instead of a 403) to hide the WAF's fingerprint.
- **Decode-then-match, not match-then-decode.** New detection logic belongs in `pwaf_patterns()` (built-in categories) or must run against every variant from `pwaf_decode()`, or it's trivially bypassed. Inputs are truncated to 2048 bytes before regex to avoid catastrophic ReDoS backtracking.
- **PHP 5.x compatibility.** The top of `waf.php` polyfills `random_int`, `random_bytes`, `array_key_first`, `hash_equals`, etc. Target runtime is PHP 5.x+ on Linux — don't use 7+/8+-only syntax or functions without a guard.

### Confidence-scoring engine (v3.8 — false-positive control)

The L1 decision is factored into `pwaf_scan_inputs(array $inputs, array $cfg)` — a **pure function** returning `null` (pass) or `['rule','param','payload']` (block). This is the unit-testable core; `pwaf_run()` just wires superglobals in and calls `pwaf_block()` on a hit. When changing detection behavior, edit `pwaf_scan_inputs`, not the loop in `pwaf_run`.

Not every pattern match blocks. `pwaf_lowconf()` maps FP-prone regexes (bare hex literals, `char(`/`cast(`, `and/or …=`, `{{…}}`, `on*=`, …) to a **signal group**. In the default `balanced` mode a high-confidence match blocks immediately, but low-confidence matches only block once **≥ `score_threshold` (default 2) distinct signal groups** fire in one request. Grouping is load-bearing: several regexes describing the *same* token (e.g. two hex-literal patterns) must share a group or a single benign value double-counts and false-positives. `fp_mode` = `strict` drops the threshold to 1 (traditional one-hit blocking); `paranoid` also widens the rule set applied to combined `CGET`/`CPOST` inputs. Toggled from the dashboard.

Two decode/FP subtleties to preserve: the `0x`-hex decoder in `pwaf_decode_once()` only emits its variant when the result is valid UTF-8 with no null byte (otherwise benign hex like `0xFF00AA` decodes to bytes that falsely trip the null-byte LFI rule); and `pwaf_is_static()` fast-passes only inert asset extensions — deliberately **not** `txt/json/xml/pdf/zip`, since `.htaccess` ForceType can route those through PHP and the response hook must still scrub any leaked flag.

Anti-bypass / anti-FP invariants baked into the engine (don't regress these — each fixed a verified evasion or false positive):
- **`FILE_BODY` scans only code-execution rules** (`upload/code/cmdi/bypass/proto`). Binary uploads (PNG/JPEG/PDF) contain null bytes and random keyword-like bytes; running `lfi`/`sqli`/etc. against file *content* falsely blocks legit uploads. Filenames (`FILE_NAME`) still get every rule (traversal/extension checks belong there).
- **Long inputs are scanned head+tail** (`pwaf_scan_inputs`): scanning only the first 2048 bytes let attackers front-pad >2048 bytes of junk to push the payload out of the window. Inputs >4096 bytes scan first 2048 + last 2048.
- **Decode pipeline carries evasion-specific variants** (`pwaf_decode_once`/`pwaf_decode`): backslash-obfuscation strip (`\s\y\stem(`→`system(`), JWT header base64-decode (catches `alg:none` in any case, since the header is too short for the base64 sniff), and MySQL version-comment unwrap (`/*!50000UNION*/`→` UNION `, which `pwaf_norm`'s full-comment-strip would otherwise erase).
- **`javascript:`/`vbscript:` schemes and tag event-handlers tolerate interstitial separators** (`java\tscript:`, `<img/onerror=`) — browsers do, so the patterns must too.
- Every regex must compile: an invalid pattern silently never matches (`@preg_match` returns false), turning a rule into a no-op. There is a validity check in the test harness; keep it at zero invalid.

## Deployment model & persistence (why the file is so defensive)

`--install` (`pwaf_install`, `waf.php:3372`) is deliberately stealthy and redundant, because in AWD the attacker has shell on the same box and will try to delete the WAF:
- Copies itself to a **random hidden dir** (`.<8 hex>/common.inc.php`) with paths hardcoded by absolute path.
- Mounts three independent auto-load strategies so removing one doesn't disable the WAF: **(A)** `.user.ini` `auto_prepend_file`, **(B)** `.htaccess` `auto_prepend_file` + `ForceType` (so even `flag.txt` is parsed as PHP through the WAF), **(C)** physical `@include_once` injected after the opening `<?php` of every discovered PHP file, tagged `@internal_handler` (idempotency marker — the installer skips already-tagged files, and `--uninstall` strips them).
- Locks core files with `chattr +i`, deploys the `inotifywait` watcher (`pwaf_deploy_watcher`, kills "immortal" webshells on filesystem events), and compiles/loads the `.so`.

The `.so` (`pwaf_ldpreload.c`) is the OS-level backstop: it hooks `execve` (blocks reverse-shell / flag-read / `LD_PRELOAD`-unset command lines), and `unlink`/`rename`/`chmod`/`remove`/`truncate` (denies any operation on files whose basename is in `protected_names[]` or whose path contains `.pwaf`). If you rename a protected WAF file in `waf.php`, update `protected_names[]` in the C file to match, or the OS-level lock won't cover it.

## Editing notes

- The admin panel (`pwaf_panel`, `waf.php:1665`) contains a large block of inlined HTML/CSS/JS emitted from PHP. The JS functions (`showTab`, `renderFullTraffic`, `toggleAutoReapUI`, replay/reap controls, etc.) are client-side code living inside PHP string output — edit them there, there is no separate frontend source.
- Config is a flat associative array; its shape and defaults are the single source of truth in `pwaf_default_cfg()` (`waf.php:120`). Add new tunables there.
- The `.pwaf_ptr` pointer file is legacy: current installs hardcode the absolute datadir path, but `pwaf_cfg_path()`/`pwaf_datadir()` still fall back to `.pwaf_ptr` and to same-dir `.pwaf.php` for compatibility with older deployments. Preserve those fallbacks.
