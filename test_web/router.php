<?php
// Front controller for the php -S test server. Loads the WAF for EVERY request
// (incl. non-existent scanner/honeypot paths), mirroring a production Apache deploy
// where the WAF runs on every hit via auto_prepend + .htaccess ForceType.
$waf = __DIR__ . '/common.inc.php';
if (is_file($waf)) require $waf;   // test runner copies ../waf.php here; absent = shop only

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$target = ($path === '/' || $path === '') ? '/index.php' : $path;
$file = realpath(__DIR__ . $target);
$root = realpath(__DIR__);

if ($file !== false && is_file($file) && strpos($file, $root) === 0) {
    if (substr($file, -4) === '.php' && strpos($path, '/lib/') !== 0) { require $file; return true; }
    if (substr($file, -4) === '.php') { http_response_code(403); echo 'Forbidden'; return true; }
    return false;   // static asset → php -S serves it (WAF already fast-passed it)
}
http_response_code(404);
echo "Not Found: " . htmlspecialchars($path);
