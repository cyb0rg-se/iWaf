#!/usr/bin/env bash
# Validates the REAL deployment: runs `php waf.php --install` (hidden .dir, physical
# injection, .user.ini/.htaccess mounts, honeypot files) on a COPY of the site, then
# drives traffic through it. The WAF loads via the injected @include_once at the top of
# each PHP file (the real mechanism) — no manual front-controller.
set -u
SRC="D:/ccccccode/PhoenixWaf/test_web"
WAF="D:/ccccccode/PhoenixWaf/waf.php"
DEP="$SRC/.deploy"
PORT=8094
B="http://127.0.0.1:$PORT"

# 1. fresh copy of the SITE SOURCE only (no runtime artifacts / this script)
rm -rf "$DEP"; mkdir -p "$DEP/lib" "$DEP/assets" "$DEP/pages"
for f in index product catalog cart checkout auth account admin review contact files fetch export render reset api suggest flag; do cp "$SRC/$f.php" "$DEP/"; done
cp "$SRC/lib/common.php" "$DEP/lib/"; cp "$SRC/assets/"* "$DEP/assets/"; cp "$SRC/pages/"* "$DEP/pages/"

echo "═══════════ 1. RUN REAL INSTALLER ═══════════"
php "$WAF" --install "$DEP" --password phoenixadmin --key testkey 2>&1 | sed 's/^/    /'

P=0; F=0; declare -a FA
ck(){ if eval "$2"; then P=$((P+1)); else F=$((F+1)); FA+=("$1"); fi; }

echo ""
echo "═══════════ 2. VERIFY STEALTH DEPLOYMENT STRUCTURE ═══════════"
HIDDEN=$(ls -d "$DEP"/.[a-z0-9]*/ 2>/dev/null | grep -E '/\.[a-z0-9]{8}/' | head -1)
ck "hidden data dir created"        "[ -n \"$HIDDEN\" ]"
ck "core moved to common.inc.php"   "[ -f \"${HIDDEN}common.inc.php\" ]"
ck "config .pwaf.php in hidden dir" "[ -f \"${HIDDEN}.pwaf.php\" ]"
ck "backup created"                 "[ -f \"${HIDDEN}.common.bak.php\" ]"
ck "integrity baseline created"     "[ -f \"${HIDDEN}.tmp_integrity\" ]"
ck ".user.ini mount"                "grep -q auto_prepend_file \"$DEP/.user.ini\""
ck ".htaccess ForceType mount"      "grep -q 'ForceType application/x-httpd-php' \"$DEP/.htaccess\""
ck ".htaccess Options -Indexes"     "grep -q 'Options -Indexes' \"$DEP/.htaccess\""
ck "physical injection tag present" "grep -q '@internal_handler' \"$DEP/index.php\""
ck "injection in nested lib/"       "grep -q '@internal_handler' \"$DEP/lib/common.php\""
ck "honeypot flag file created"     "[ -f \"$DEP/flag\" ] && [ -f \"$DEP/flag.txt\" ]"
ck "waf.php source untouched"       "! head -c 200 \"$WAF\" | grep -q 'internal_handler'"

echo ""
echo "═══════════ 3. DRIVE TRAFFIC THROUGH THE INSTALLED WAF (php -S, injection-loaded) ═══════════"
# No router: php -S runs each real .php file, whose injected @include_once loads the WAF.
php -d error_reporting=0 -d display_errors=0 -S 127.0.0.1:$PORT -t "$DEP" >/dev/null 2>&1 &
SRV=$!; trap "kill $SRV 2>/dev/null" EXIT
for i in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/index.php" 2>/dev/null)" = "200" ] && break; sleep 0.3; done
BLK='请求被拦截'; BLK2='请求已被拦截'
resp(){ curl -s -w $'\n%{http_code}' "$@" 2>/dev/null; }
pass(){ local n="$1" m="$2"; shift 2; local o; o=$(resp "$@"); local c="${o##*$'\n'}" b="${o%$'\n'*}"
  if [ "$c" = "200" ] && echo "$b"|grep -qF "$m" && ! echo "$b"|grep -q "$BLK2"; then P=$((P+1)); else F=$((F+1)); FA+=("PASS [$n] http=$c"); fi; }
block(){ local n="$1"; shift; local o; o=$(resp "$@"); local c="${o##*$'\n'}" b="${o%$'\n'*}"
  if [ "$c" = "403" ] || echo "$b"|grep -q "$BLK2"; then P=$((P+1)); else F=$((F+1)); FA+=("BLOCK [$n] http=$c"); fi; }

pass  "installed-home"      "Everything for your everyday" "$B/index.php"
pass  "installed-catalog"   "Blue Denim Jacket"    "$B/catalog.php"
pass  "installed-product"   "Wireless Headphones"  "$B/product.php?id=3"
pass  "installed-benign-q"  "Wireless"             "$B/catalog.php" -G --data-urlencode "q=wireless"
block "installed-sqli"      "$B/catalog.php" -G --data-urlencode "q=x' UNION SELECT user,pass FROM users-- -"
block "installed-xss"       "$B/render.php"  -G --data-urlencode "name=<script>alert(1)</script>"
block "installed-lfi"       "$B/files.php"   -G --data-urlencode "view=../../../../etc/passwd"
block "installed-rce"       "$B/export.php"  -G --data-urlencode "fmt=x;id"
block "installed-ssrf"      "$B/fetch.php"   -G --data-urlencode "url=http://169.254.169.254/"
# flag leak scrubbed through the injected WAF
REAL='flag{D3M0SH0P_PR0_r00t_a1b2c3d4e5f6}'
b=$(curl -s "$B/flag.php?fmt=plain"); ck "installed-flag-scrubbed" "! echo \"\$b\" | grep -qF '$REAL'"
# honeypot decoy files serve the fake flag (static content planted by installer)
b=$(curl -s "$B/flag.txt"); ck "honeypot-flag.txt-fake" "echo \"\$b\" | grep -q 'flag{'"
# panel reachable through the injected WAF
b=$(curl -s "$B/index.php?waf_key=testkey"); ck "panel-reachable" "echo \"\$b\" | grep -q '管理面板'"

echo ""
echo "═══════════════════════════════════════════════"
echo "RESULT: $P passed, $F failed  (total $((P+F)))"
if [ $F -gt 0 ]; then printf ' ✗ %s\n' "${FA[@]}"; kill $SRV 2>/dev/null; rm -rf "$DEP"; exit 1; fi
echo "✓ REAL-INSTALL DEPLOYMENT VALIDATED — stealth topology + injection-loaded WAF + honeypots all OK"
kill $SRV 2>/dev/null; rm -rf "$DEP"
