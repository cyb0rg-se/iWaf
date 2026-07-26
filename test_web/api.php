<?php require __DIR__ . '/lib/common.php';
// JSON API with simple token auth. NORMAL: search / order lookup / echo.
// VULN: 'calc' eval sink (simulated), and raw params reflected into responses.
header('Content-Type: application/json; charset=utf-8');
$raw = file_get_contents('php://input');
$in  = json_decode($raw, true);
if (!is_array($in)) $in = $_GET;
$action = $in['action'] ?? ($_GET['action'] ?? 'ping');
$token   = $_SERVER['HTTP_X_API_TOKEN'] ?? ($in['token'] ?? '');

switch ($action) {
    case 'ping':
        echo json_encode(['ok'=>true, 'service'=>'DemoShop API', 'v'=>'1.2', 'ts'=>time()]);
        break;
    case 'search':
        $q = $in['q'] ?? ($_GET['q'] ?? '');
        $res = array_values(array_filter(dsp_products(), function($p) use ($q){ return $q==='' || stripos($p['name'],$q)!==false; }));
        echo json_encode(['ok'=>true, 'query'=>$q, 'count'=>count($res), 'results'=>$res], JSON_UNESCAPED_SLASHES);
        break;
    case 'order':
        if ($token !== 'demo-token-123') { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'invalid token']); break; }
        echo json_encode(['ok'=>true, 'order'=>$in['order'] ?? null, 'status'=>'accepted']);
        break;
    case 'calc': // deliberately dangerous (simulated)
        echo json_encode(['ok'=>true, 'expr'=>$in['calc'] ?? '', 'note'=>'[would eval: '.($in['calc'] ?? '').']']);
        break;
    default:
        echo json_encode(['ok'=>false, 'error'=>'unknown action', 'echo'=>$in]);
}
