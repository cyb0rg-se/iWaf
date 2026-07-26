<?php require __DIR__ . '/lib/common.php';
// VULN: command injection via 'fmt' (SIMULATED). NORMAL: export catalog as csv/json.
$fmt = isset($_GET['fmt']) ? $_GET['fmt'] : 'csv';
dsp_header('Export');
echo "<h1>Export Catalog</h1>";
echo "<div class=exportbtns><a class=btn href='?fmt=csv'>CSV</a> <a class='btn ghost' href='?fmt=json'>JSON</a></div>";
echo "<p class=debug>[would run: /usr/bin/report --format " . e($fmt) . " catalog.dat]</p>";
if ($fmt === 'json') echo "<pre>" . e(json_encode(dsp_products(), JSON_PRETTY_PRINT)) . "</pre>";
else { echo "<pre>id,name,cat,price\n"; foreach (dsp_products() as $p) echo e("{$p['id']},{$p['name']},{$p['cat']},{$p['price']}\n"); echo "</pre>"; }
dsp_footer();
