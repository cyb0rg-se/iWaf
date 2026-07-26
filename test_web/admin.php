<?php require __DIR__ . '/lib/common.php';
// NORMAL: admin dashboard (users + orders). VULN: SQLi in user search, IDOR-ish role check via cookie.
$u = dsp_current_user();
$isAdmin = ($u && $u['role'] === 'admin') || (($_COOKIE['role'] ?? '') === 'admin'); // VULN: trusts cookie
if (!$isAdmin) { dsp_header('Admin'); echo "<h1>403</h1><p>Admins only.</p>"; dsp_footer(); exit; }
$search = isset($_GET['u']) ? $_GET['u'] : '';
$sql = "SELECT id,user,role,email FROM users WHERE user LIKE '%$search%'";
$rows = dsp_users();
if ($search !== '') $rows = array_filter($rows, function($r) use ($search){ return stripos($r['user'],$search)!==false; });
dsp_header('Admin', '');
?>
<h1>Admin Dashboard</h1>
<form class=filters><input name=u value="<?= e($search) ?>" placeholder='search users'><button class=btn>Search</button></form>
<p class=debug>Query: <?= e($sql) ?></p>
<table class=admin><tr><th>ID</th><th>User</th><th>Role</th><th>Email</th></tr>
<?php foreach ($rows as $r): ?>
  <tr><td><?= (int)$r['id'] ?></td><td><?= e($r['user']) ?></td><td><?= e($r['role']) ?></td><td><?= e($r['email']) ?></td></tr>
<?php endforeach; ?>
</table>
<h2>Recent orders</h2>
<table class=admin><tr><th>Order</th><th>Customer</th><th>Total</th></tr>
<?php foreach (dsp_json_read('orders.json') as $o): ?>
  <tr><td>#<?= e($o['id']) ?></td><td><?= e($o['name']) ?></td><td>$<?= e($o['total']) ?></td></tr>
<?php endforeach; ?>
</table>
<?php dsp_footer();
