<?php require __DIR__ . '/lib/common.php';
dsp_header('Home');
?>
<section class=hero>
  <h1>Everything for your everyday</h1>
  <p>Shoes, audio, kitchen and more — free shipping over $50.</p>
  <a class=btn href=/catalog.php>Shop the catalog</a>
</section>
<h2>Featured</h2>
<ul class=grid>
<?php foreach (array_slice(dsp_products(), 0, 6) as $p): ?>
  <li class=product>
    <a href="/product.php?id=<?= (int)$p['id'] ?>"><span class=pname><?= e($p['name']) ?></span></a>
    <div class=meta><span class=price>$<?= e($p['price']) ?></span><span class=rating>★ <?= e($p['rating']) ?></span></div>
    <div class=cat><?= e($p['cat']) ?></div>
  </li>
<?php endforeach; ?>
</ul>
<?php dsp_footer();
