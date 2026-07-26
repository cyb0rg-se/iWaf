<?php require __DIR__ . '/lib/common.php';
// NORMAL: personal file manager — upload, list, view content pages.
// VULN: unrestricted upload (keeps ext) + LFI via 'view' (include user-named page).
$msg = '';
$updir = dsp_data('uploads'); if (!is_dir($updir)) @mkdir($updir, 0777, true);
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_FILES['file']['name'])) {
    $name = basename($_FILES['file']['name']);
    @move_uploaded_file($_FILES['file']['tmp_name'], $updir . '/' . $name);
    $msg = "<span class=ok>Uploaded " . e($name) . "</span>";
}
$view = isset($_GET['view']) ? $_GET['view'] : '';
dsp_header('Files');
echo "<h1>File Manager</h1>"; dsp_flash($msg);
echo "<form method=post enctype='multipart/form-data' class=inline><input type=file name=file><button class=btn>Upload</button></form>";
echo "<h2>Help pages</h2><ul class=filelist>";
foreach (['welcome','faq','terms'] as $doc) echo "<li><a href='?view={$doc}'>{$doc}</a></li>";
echo "</ul>";
if ($view !== '') {
    $path = __DIR__ . '/pages/' . $view . '.php';   // VULN: LFI
    echo "<div class=card>";
    if (file_exists($path)) include $path; else echo "<p>No such page: " . e($view) . "</p>";
    echo "</div>";
}
dsp_footer();
