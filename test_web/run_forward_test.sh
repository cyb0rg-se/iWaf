#!/usr/bin/env bash
# Verifies the blind-spray/forward + flagsub interaction doesn't regress core defense:
# with forwarding ENABLED, flags must still be scrubbed, normal pages must still work,
# and requests must not hang (non-blocking mirror + fast-refusing target).
set -u
HERE="D:/ccccccode/PhoenixWaf/test_web"
WAF="D:/ccccccode/PhoenixWaf/waf.php"; PORT=8096; B="http://127.0.0.1:$PORT"
cp "$WAF" "$HERE/common.inc.php"; rm -rf "$HERE/data"
cat > "$HERE/.pwaf.php" <<PHP
<?php return array(
 'enabled'=>true,'key'=>'testkey','hash'=>'','datadir'=>'$HERE','log'=>'$HERE/.pwaf_log',
 'rate_db'=>'$HERE/.pwaf_rate','integrity_db'=>'$HERE/.pwaf_int','fake_flag'=>'flag{fake000}',
 'stealth'=>false,'auto_ban'=>false,'access_log'=>true,'rate_limit'=>1000000,
 'fp_mode'=>'balanced','static_bypass'=>true,'score_threshold'=>2,'honeypots'=>array(),
 'whitelist'=>array(),'blacklist'=>array(),'checker_ips'=>array(),'custom_rules'=>array(),
 // forwarding ON, to a fast-refusing local port (9) so the mirror never hangs the request
 'forward_enabled'=>true,'forward_targets'=>array(array('host'=>'127.0.0.1','port'=>9,'cidr'=>'','enabled'=>true)),
 'rules'=>array('sqli'=>true,'cmdi'=>true,'lfi'=>true,'xss'=>true,'code'=>true,'ssrf'=>true,'xxe'=>true,
   'unserialize'=>true,'upload'=>true,'response'=>true,'bypass'=>true,'nosqli'=>true,'ssti'=>true,'jwt'=>true,'proto'=>true),
 'webroot'=>'$HERE');
PHP
php -d error_reporting=0 -d display_errors=0 -S 127.0.0.1:$PORT -t "$HERE" "$HERE/router.php" >/dev/null 2>&1 &
SRV=$!; trap "kill $SRV 2>/dev/null" EXIT
for i in $(seq 1 40); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = "200" ] && break; sleep 0.3; done

P=0; F=0; declare -a FA
REAL='flag{D3M0SH0P_PR0_r00t_a1b2c3d4e5f6}'
# 1. flag body still scrubbed with forwarding enabled
b=$(curl -s "$B/flag.php?fmt=plain"); if echo "$b"|grep -qF "$REAL"; then F=$((F+1)); FA+=("flag leaked with forward on"); else P=$((P+1)); fi
b=$(curl -s "$B/flag.php?fmt=b64");   x=$(php -r "echo base64_encode('$REAL');"); if echo "$b"|grep -qF "$x"; then F=$((F+1)); FA+=("b64 flag leaked with forward on"); else P=$((P+1)); fi
# 2. normal page still works + not blocked
b=$(curl -s -w '\n%{http_code}' "$B/"); c="${b##*$'\n'}"; body="${b%$'\n'*}"
if [ "$c" = "200" ] && echo "$body"|grep -q "Everything for your everyday"; then P=$((P+1)); else F=$((F+1)); FA+=("home broke with forward on (http=$c)"); fi
# 3. attack still blocked with forward on
c=$(curl -s -o /dev/null -w '%{http_code}' "$B/render.php?name=%3Cscript%3Ealert(1)%3C/script%3E"); if [ "$c" = "403" ]; then P=$((P+1)); else F=$((F+1)); FA+=("attack not blocked with forward on (http=$c)"); fi
# 4. request must not hang: 3 requests should finish well under 6s total (fast-refuse target)
t0=$(date +%s%N); for i in 1 2 3; do curl -s -o /dev/null --max-time 5 "$B/catalog.php"; done; t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 )); if [ $ms -lt 6000 ]; then P=$((P+1)); else F=$((F+1)); FA+=("forward hangs requests (${ms}ms for 3 reqs)"); fi

echo "forward+flagsub interaction: $P passed, $F failed (3-req time: ${ms}ms)"
if [ $F -gt 0 ]; then printf ' ✗ %s\n' "${FA[@]}"; exit 1; fi
echo "✓ forward/spray does not regress flag scrubbing, normal traffic, or latency"
