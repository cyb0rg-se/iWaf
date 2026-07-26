<?php require __DIR__ . '/lib/common.php';
// NORMAL: search + category filter + sort + pagination over the catalog.
// VULN: q/cat/sort/page concatenated into a query string (reflected) — SQLi across multiple params.
$q    = isset($_GET['q'])    ? $_GET['q']    : '';
$cat  = isset($_GET['cat'])  ? $_GET['cat']  : '';
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$per  = 4;

$sql = "SELECT * FROM products WHERE 1=1"
     . ($q   !== '' ? " AND name LIKE '%$q%'" : '')
     . ($cat !== '' ? " AND cat = '$cat'"     : '')
     . " ORDER BY $sort LIMIT $per OFFSET " . (($page-1)*$per);

$items = dsp_products();
if ($q !== '')   $items = array_filter($items, function($p) use ($q)   { return stripos($p['name'], $q) !== false; });
if ($cat !== '') $items = array_filter($items, function($p) use ($cat) { return strcasecmp($p['cat'], $cat) === 0; });
$items = array_values($items);
usort($items, function($a,$b) use ($sort) {
    if ($sort === 'price') return $a['price'] <=> $b['price'];
    if ($sort === 'rating') return $b['rating'] <=> $a['rating'];
    return strcmp($a['name'], $b['name']);
});
$total = count($items);
$items = array_slice($items, ($page-1)*$per, $per);

dsp_header('Catalog', 'catalog');
?>
<h1>Catalog</h1>
<form class=filters method=get>
  <input name=q value="<?= e($q) ?>" placeholder="search products">
  <select name=cat>
    <option value="">All categories</option>
    <?php foreach (['shoes','clothing','audio','accessory','kitchen','fitness'] as $c): ?>
      <option value="<?= e($c) ?>" <?= $c===$cat?'selected':'' ?>><?= e($c) ?></option>
    <?php endforeach; ?>
  </select>
  <select name=sort>
    <?php foreach (['name'=>'Name','price'=>'Price','rating'=>'Rating'] as $k=>$v): ?>
      <option value="<?= e($k) ?>" <?= $k===$sort?'selected':'' ?>><?= e($v) ?></option>
    <?php endforeach; ?>
  </select>
  <button class=btn>Filter</button>
</form>
<p class=debug>Query: <?= e($sql) ?></p>
<ul class=grid>
<?php foreach ($items as $p): ?>
  <li class=product><a href="/product.php?id=<?= (int)$p['id'] ?>"><span class=pname><?= e($p['name']) ?></span></a>
    <div class=meta><span class=price>$<?= e($p['price']) ?></span><span class=rating>★ <?= e($p['rating']) ?></span></div></li>
<?php endforeach; ?>
<?php if (!$items): ?><li class=empty>No products matched "<?= e($q) ?>".</li><?php endif; ?>
</ul>
<nav class=pager>
<?php $pages = max(1, (int)ceil($total/$per)); for ($i=1;$i<=$pages;$i++): ?>
  <a class="<?= $i===$page?'on':'' ?>" href="?q=<?= urlencode($q) ?>&cat=<?= urlencode($cat) ?>&sort=<?= urlencode($sort) ?>&page=<?= $i ?>"><?= $i ?></a>
<?php endfor; ?>
</nav>
<?php dsp_footer();
