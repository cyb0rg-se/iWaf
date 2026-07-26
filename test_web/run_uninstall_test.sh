#!/usr/bin/env bash
# Verifies the install -> uninstall roundtrip fully reverts the deployment:
# mounts removed, physical injection stripped, hidden dir destroyed, and the WAF
# no longer runs (an attack that was blocked while installed now passes through).
set -u
SRC="D:/ccccccode/PhoenixWaf/test_web"; WAF="D:/ccccccode/PhoenixWaf/waf.php"
DEP="$SRC/.deploy_un"; PORT=8097; B="http://127.0.0.1:$PORT"

rm -rf "$DEP"; mkdir -p "$DEP/lib" "$DEP/assets" "$DEP/pages"
for f in index product catalog cart checkout auth account admin review contact files fetch export render reset api suggest flag; do cp "$SRC/$f.php" "$DEP/"; done
cp "$SRC/lib/common.php" "$DEP/lib/"; cp "$SRC/assets/"* "$DEP/assets/"; cp "$SRC/pages/"* "$DEP/pages/"
# capture pristine hashes of the app files to verify byte-perfect restoration
BEFORE=$(cd "$DEP" && find . -name '*.php' -exec md5sum {} \; | sort)

P=0; F=0; declare -a FA
ck(){ if eval "$2"; then P=$((P+1)); else F=$((F+1)); FA+=("$1"); fi; }

echo "═══════════ 1. INSTALL ═══════════"
php "$WAF" --install "$DEP" --password pw --key testkey 2>&1 | sed 's/^/  /' | tail -6
ck "injection present after install" "grep -q '@internal_handler' \"$DEP/index.php\""
ck ".user.ini mounted"               "grep -q auto_prepend_file \"$DEP/.user.ini\""
ck ".htaccess mounted"               "grep -q auto_prepend_file \"$DEP/.htaccess\""
HID=$(ls -d "$DEP"/.[a-z0-9]*/ 2>/dev/null | grep -E '/\.[a-z0-9]{8}/' | head -1)
ck "hidden dir exists"               "[ -n \"$HID\" ]"

# confirm WAF actually runs while installed (attack blocked)
php -d error_reporting=0 -d display_errors=0 -S 127.0.0.1:$PORT -t "$DEP" >/dev/null 2>&1 &
S1=$!; for i in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/index.php" 2>/dev/null)" = "200" ] && break; sleep 0.3; done
c=$(curl -s -o /dev/null -w '%{http_code}' "$B/render.php?name=%3Cscript%3Ealert(1)%3C/script%3E")
ck "attack blocked while installed (403)" "[ \"$c\" = \"403\" ]"
kill $S1 2>/dev/null; sleep 0.5

echo "═══════════ 2. UNINSTALL ═══════════"
php "$WAF" --uninstall "$DEP" 2>&1 | sed 's/^/  /' | tail -4
ck "injection stripped"        "! grep -rq '@internal_handler' \"$DEP\""
ck ".user.ini prepend removed" "! ( [ -f \"$DEP/.user.ini\" ] && grep -q auto_prepend_file \"$DEP/.user.ini\" )"
ck ".htaccess prepend removed" "! ( [ -f \"$DEP/.htaccess\" ] && grep -q auto_prepend_file \"$DEP/.htaccess\" )"
ck ".htaccess ForceType removed" "! ( [ -f \"$DEP/.htaccess\" ] && grep -q 'ForceType application/x-httpd-php' \"$DEP/.htaccess\" )"
ck "hidden dir destroyed"      "[ -z \"$(ls -d "$DEP"/.[a-z0-9]*/ 2>/dev/null | grep -E '/\.[a-z0-9]{8}/')\" ]"
# app files restored byte-for-byte
AFTER=$(cd "$DEP" && find . -name '*.php' -exec md5sum {} \; | sort)
ck "app PHP files byte-identical to pre-install" "[ \"$BEFORE\" = \"$AFTER\" ]"

echo "═══════════ 3. WAF NO LONGER RUNS ═══════════"
php -d error_reporting=0 -d display_errors=0 -S 127.0.0.1:$PORT -t "$DEP" >/dev/null 2>&1 &
S2=$!; for i in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/index.php" 2>/dev/null)" = "200" ] && break; sleep 0.3; done
# same attack now passes (WAF gone) — the app reflects it, HTTP 200, no block page
o=$(curl -s -w '\n%{http_code}' "$B/render.php?name=%3Cscript%3Ealert(1)%3C/script%3E"); c="${o##*$'\n'}"; b="${o%$'\n'*}"
ck "attack NOT blocked after uninstall (WAF gone)" "[ \"$c\" = \"200\" ] && ! echo \"$b\" | grep -q '请求已被拦截'"
kill $S2 2>/dev/null

echo ""
echo "═══════════════════════════════════════════════"
echo "RESULT: $P passed, $F failed"
if [ $F -gt 0 ]; then printf ' ✗ %s\n' "${FA[@]}"; rm -rf "$DEP"; exit 1; fi
echo "✓ INSTALL→UNINSTALL ROUNDTRIP CLEAN — mounts reverted, injection stripped, files restored, WAF fully removed"
rm -rf "$DEP"
