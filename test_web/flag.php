<?php require __DIR__ . '/lib/common.php';
// Simulates a protected secret leaking into the response in various encodings —
// exercises the WAF L2 response hook (flag scrubbing). Real AWD box: the protected flag.
$real = 'flag{D3M0SH0P_PR0_r00t_a1b2c3d4e5f6}';
$fmt = isset($_GET['fmt']) ? $_GET['fmt'] : 'plain';
header('Content-Type: text/plain; charset=utf-8');
switch ($fmt) {
    case 'b64':  echo "token=" . base64_encode($real); break;
    case 'hex':  echo "h=" . bin2hex($real); break;
    case 'rev':  echo strrev($real); break;
    case 'url':  echo rawurlencode($real); break;
    case 'json': echo json_encode(['secret'=>$real]); break;
    case 'html': echo "<p>debug secret: $real</p>"; break;
    default:     echo "internal debug — flag is $real\n";
}
