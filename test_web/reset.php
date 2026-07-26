<?php require __DIR__ . '/lib/common.php';
// NORMAL: password-reset request (emails a token — simulated). VULN: reflected email/token params.
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $token = substr(md5($email . 'salt'), 0, 12);
    $msg = "<span class=ok>If an account exists for " . e($email) . ", a reset link was sent.</span>";
}
$tok = isset($_GET['token']) ? $_GET['token'] : '';
dsp_header('Password Reset');
echo "<h1>Reset your password</h1>"; dsp_flash($msg);
if ($tok !== '') echo "<p>Using reset token: <code>" . e($tok) . "</code></p>";
echo "<form method=post class=stack><input name=email placeholder='your account email'><button class=btn>Send reset link</button></form>";
dsp_footer();
