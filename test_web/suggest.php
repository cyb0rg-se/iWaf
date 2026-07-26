<?php require __DIR__ . '/lib/common.php';
// AJAX search-suggest endpoint (used by the catalog's live search). NORMAL: returns JSON matches.
header('Content-Type: application/json; charset=utf-8');
$q = isset($_GET['term']) ? $_GET['term'] : '';
$out = [];
foreach (dsp_products() as $p) if ($q !== '' && stripos($p['name'], $q) !== false) $out[] = $p['name'];
echo json_encode(['term'=>$q, 'suggestions'=>$out], JSON_UNESCAPED_UNICODE);
