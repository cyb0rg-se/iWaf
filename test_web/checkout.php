<?php require __DIR__ . '/lib/common.php';
// NORMAL: checkout form -> creates an order (JSON). VULN: name/address reflected (XSS) + header use.
$msg = '';
$prods = []; foreach (dsp_products() as $p) $prods[$p['id']] = $p;
$cart = $_SESSION['cart'] ?? [];
$total = 0; foreach ($cart as $pid=>$q) if (isset($prods[$pid])) $total += $prods[$pid]['price']*$q;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? ''; $addr = $_POST['addr'] ?? '';
    $orders = dsp_json_read('orders.json');
    $oid = 1000 + count($orders);
    $orders[] = ['id'=>$oid, 'name'=>$name, 'addr'=>$addr, 'total'=>number_format($total,2), 'ts'=>date('Y-m-d H:i')];
    dsp_json_write('orders.json', array_slice($orders,-50));
    $_SESSION['cart'] = [];
    $msg = "<span class=ok>Order #{$oid} placed. Thank you, " . e($name) . "!</span>";
}
dsp_header('Checkout');
echo "<h1>Checkout</h1>"; dsp_flash($msg);
echo "<p>Order total: <b>\$" . e(number_format($total,2)) . "</b></p>";
echo "<form method=post class=stack><input name=name placeholder='full name'>"
   . "<textarea name=addr placeholder='shipping address'></textarea>"
   . "<button class=btn>Place order</button></form>";
dsp_footer();
