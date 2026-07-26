<?php require __DIR__ . '/lib/common.php';
// NORMAL: register / login / logout (session, users.json). VULN: SQLi auth-bypass sink.
$do = isset($_GET['do']) ? $_GET['do'] : 'login';
$msg = '';
if ($do === 'logout') { session_destroy(); header('Location: /'); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = isset($_POST['user']) ? $_POST['user'] : '';
    $pass = isset($_POST['pass']) ? $_POST['pass'] : '';
    if (($_POST['mode'] ?? '') === 'register') {
        $users = dsp_users();
        $exists = false; foreach ($users as $u) if ($u['user'] === $user) $exists = true;
        if ($user === '' || $pass === '') { $msg = "<span class=err>Username and password required.</span>"; }
        elseif ($exists) { $msg = "<span class=err>That username is taken.</span>"; }
        else {
            $nid = 1; foreach ($users as $u) $nid = max($nid, $u['id']+1);
            $users[] = ['id'=>$nid,'user'=>$user,'pass'=>$pass,'role'=>'user','email'=>$user.'@demoshop.test'];
            dsp_json_write('users.json', $users);
            $_SESSION['uid'] = $nid;
            header('Location: /account.php'); exit;
        }
    } else {
        $sql = "SELECT * FROM users WHERE user='$user' AND pass='$pass'"; // vulnerable pattern
        $hit = null; foreach (dsp_users() as $u) if ($u['user']===$user && $u['pass']===$pass) $hit = $u;
        if ($hit) { $_SESSION['uid'] = $hit['id']; header('Location: /account.php'); exit; }
        $msg = "<span class=err>Invalid credentials.</span>";
    }
}
dsp_header('Login');
?>
<div class=authbox>
  <div class=tabpanel>
    <h1>Sign in</h1><?= $msg ? "<p class=flash>$msg</p>" : '' ?>
    <form method=post><input type=hidden name=mode value=login>
      <input name=user placeholder=username value="<?= e($_POST['user'] ?? '') ?>">
      <input name=pass type=password placeholder=password>
      <button class=btn>Sign in</button></form>
    <p class=hint>Try <code>alice / wonderland</code> or <code>admin / sup3rs3cret</code></p>
  </div>
  <div class=tabpanel>
    <h1>Create account</h1>
    <form method=post><input type=hidden name=mode value=register>
      <input name=user placeholder='choose a username'>
      <input name=pass type=password placeholder='choose a password'>
      <button class='btn ghost'>Register</button></form>
  </div>
</div>
<?php dsp_footer();
