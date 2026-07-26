<?php require __DIR__ . '/lib/common.php';
// VULN: SQLi/IDOR via id. NORMAL: product detail + add-to-cart.
$id = isset($_GET['id']) ? $_GET['id'] : '1';
$sql = "SELECT * FROM products WHERE id = $id";
$found = null;
foreach (dsp_products() as $p) if ((string)$p['id'] === (string)$id) $found = $p;
dsp_header($found ? $found['name'] : 'Product');
if ($found):
?>
<article class=detail>
  <h1><?= e($found['name']) ?></h1>
  <div class=meta><span class=price>$<?= e($found['price']) ?></span> · ★ <?= e($found['rating']) ?> · <?= e($found['cat']) ?></div>
  <p>In stock: <?= (int)$found['stock'] ?></p>
  <form method=post action=/cart.php><input type=hidden name=add value="<?= (int)$found['id'] ?>"><button class=btn>Add to cart</button></form>
</article>
<?php else: ?>
<p>Product #<?= e($id) ?> not found.</p>
<?php endif; ?>
<p class=debug>Query: <?= e($sql) ?></p>
<?php dsp_footer();
