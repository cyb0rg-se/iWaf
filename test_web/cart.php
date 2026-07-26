<?php require __DIR__ . '/lib/common.php';
// NORMAL: session-based cart (add/remove/qty). Multi-step business flow.
if (!isset($_SESSION['cart'])) $_SESSION['cart'] = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['add']))  { $i=(int)$_POST['add']; $_SESSION['cart'][$i]=($_SESSION['cart'][$i]??0)+1; }
    if (isset($_POST['del']))  { unset($_SESSION['cart'][(int)$_POST['del']]); }
    if (isset($_POST['clear'])){ $_SESSION['cart']=[]; }
    header('Location: /cart.php'); exit;
}
$prods = [];
foreach (dsp_products() as $p) $prods[$p['id']] = $p;
$total = 0;
dsp_header('Cart');
echo "<h1>Your Cart</h1>";
if (!$_SESSION['cart']) { echo "<p class=empty>Your cart is empty. <a href=/catalog.php>Browse products</a>.</p>"; }
else {
    echo "<table class=cart><tr><th>Item</th><th>Qty</th><th>Price</th><th></th></tr>";
    foreach ($_SESSION['cart'] as $pid=>$qty) {
        if (!isset($prods[$pid])) continue;
        $p = $prods[$pid]; $line = $p['price']*$qty; $total += $line;
        echo "<tr><td>" . e($p['name']) . "</td><td>{$qty}</td><td>\$" . e(number_format($line,2)) . "</td>"
           . "<td><form method=post><input type=hidden name=del value='{$pid}'><button class='btn small'>Remove</button></form></td></tr>";
    }
    echo "<tr class=total><td colspan=2>Total</td><td>\$" . e(number_format($total,2)) . "</td><td></td></tr></table>";
    echo "<div class=cartactions><a class=btn href=/checkout.php>Checkout</a>"
       . "<form method=post><button class='btn ghost' name=clear value=1>Clear</button></form></div>";
}
dsp_footer();
