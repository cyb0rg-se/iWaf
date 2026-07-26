<?php
/**
 * DemoShop Pro — shared foundation for the (deliberately vulnerable) WAF test target.
 * No database: state lives in $_SESSION and JSON files under data/. Normal business
 * logic works end-to-end; each page carries intentional vulnerabilities so the WAF
 * can be validated. Command/code/SSRF sinks are SIMULATED (echoed) so the host is
 * never harmed — the WAF blocks attack payloads before they reach any sink.
 */
if (defined('DSP_LIB')) return;
define('DSP_LIB', 1);

if (session_status() !== PHP_SESSION_ACTIVE) @session_start();

function dsp_data($name) {
    $d = dirname(__DIR__) . '/data';
    if (!is_dir($d)) @mkdir($d, 0777, true);
    return $d . '/' . $name;
}
function dsp_json_read($name, $default = []) {
    $f = dsp_data($name);
    return file_exists($f) ? (json_decode(file_get_contents($f), true) ?: $default) : $default;
}
function dsp_json_write($name, $data) {
    file_put_contents(dsp_data($name), json_encode($data, JSON_UNESCAPED_UNICODE));
}

function dsp_users() {
    $f = dsp_data('users.json');
    if (!file_exists($f)) {
        dsp_json_write('users.json', [
            ['id'=>1, 'user'=>'alice', 'pass'=>'wonderland', 'role'=>'user',  'email'=>'alice@demoshop.test'],
            ['id'=>2, 'user'=>'bob',   'pass'=>'builder123', 'role'=>'user',  'email'=>'bob@demoshop.test'],
            ['id'=>3, 'user'=>'admin', 'pass'=>'sup3rs3cret','role'=>'admin', 'email'=>'admin@demoshop.test'],
        ]);
    }
    return dsp_json_read('users.json');
}

function dsp_products() {
    return [
        ['id'=>1, 'name'=>'Red Running Shoes',   'cat'=>'shoes',    'price'=>79.99, 'stock'=>12, 'rating'=>4.5],
        ['id'=>2, 'name'=>'Blue Denim Jacket',   'cat'=>'clothing', 'price'=>119.00,'stock'=>5,  'rating'=>4.1],
        ['id'=>3, 'name'=>'Wireless Headphones', 'cat'=>'audio',    'price'=>199.99,'stock'=>30, 'rating'=>4.8],
        ['id'=>4, 'name'=>'Leather Wallet',      'cat'=>'accessory','price'=>45.50, 'stock'=>0,  'rating'=>3.9],
        ['id'=>5, 'name'=>'Stainless Bottle',    'cat'=>'kitchen',  'price'=>24.99, 'stock'=>77, 'rating'=>4.6],
        ['id'=>6, 'name'=>'Yoga Mat Pro',        'cat'=>'fitness',  'price'=>32.00, 'stock'=>18, 'rating'=>4.3],
        ['id'=>7, 'name'=>'Mechanical Keyboard', 'cat'=>'audio',    'price'=>89.00, 'stock'=>9,  'rating'=>4.7],
        ['id'=>8, 'name'=>'Canvas Backpack',     'cat'=>'accessory','price'=>54.00, 'stock'=>22, 'rating'=>4.4],
        ['id'=>9, 'name'=>'Ceramic Mug Set',     'cat'=>'kitchen',  'price'=>18.50, 'stock'=>50, 'rating'=>4.0],
        ['id'=>10,'name'=>'Trail Running Socks',  'cat'=>'shoes',    'price'=>12.99, 'stock'=>200,'rating'=>4.2],
    ];
}

function dsp_current_user() {
    if (empty($_SESSION['uid'])) return null;
    foreach (dsp_users() as $u) if ($u['id'] === $_SESSION['uid']) return $u;
    return null;
}

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function dsp_header($title, $active = '') {
    $u = dsp_current_user();
    $cart = isset($_SESSION['cart']) ? array_sum($_SESSION['cart']) : 0;
    $nav = [
        'catalog'=>['Catalog','/catalog.php'], 'reviews'=>['Reviews','/review.php'],
        'files'=>['Files','/files.php'], 'contact'=>['Contact','/contact.php'],
    ];
    echo "<!DOCTYPE html><html lang=en><head><meta charset=utf-8>"
       . "<meta name=viewport content='width=device-width,initial-scale=1'>"
       . "<title>" . e($title) . " · DemoShop Pro</title>"
       . "<link rel=stylesheet href=/assets/style.css></head><body>"
       . "<header class=topbar><a class=brand href=/>🛍 DemoShop<span>Pro</span></a><nav class=mainnav>";
    foreach ($nav as $k=>$v) {
        $cls = ($active === $k) ? ' class=active' : '';
        echo "<a$cls href='" . e($v[1]) . "'>" . e($v[0]) . "</a>";
    }
    echo "</nav><div class=useractions><a href=/cart.php class=cart>Cart <span class=badge>{$cart}</span></a>";
    if ($u) {
        echo "<span class=hi>Hi, " . e($u['user']) . "</span>";
        if ($u['role'] === 'admin') echo "<a href=/admin.php class=adminlink>Admin</a>";
        echo "<a href='/auth.php?do=logout'>Logout</a>";
    } else {
        echo "<a href=/auth.php>Login</a>";
    }
    echo "</div></header><main class=wrap>";
}
function dsp_footer() {
    echo "</main><footer class=foot><div>DemoShop Pro — a deliberately vulnerable demo for WAF testing</div>"
       . "<div class=muted>© 2026 DemoShop · Secured by PhoenixWAF</div></footer>"
       . "<script src=/assets/app.js></script></body></html>";
}
function dsp_flash($msg, $type = 'ok') {
    if ($msg !== '') echo "<div class='flash $type'>" . $msg . "</div>";
}
