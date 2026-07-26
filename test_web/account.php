<?php require __DIR__ . '/lib/common.php';
// NORMAL: view/edit profile (requires login). VULN: reflected/stored XSS in profile fields.
$u = dsp_current_user();
if (!$u) { header('Location: /auth.php'); exit; }
$profiles = dsp_json_read('profiles.json');
$mine = $profiles[$u['id']] ?? ['display'=>$u['user'], 'city'=>'', 'bio'=>''];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mine = ['display'=>$_POST['display'] ?? '', 'city'=>$_POST['city'] ?? '', 'bio'=>$_POST['bio'] ?? ''];
    $profiles[$u['id']] = $mine; dsp_json_write('profiles.json', $profiles);
}
dsp_header('My Account');
?>
<h1>My Account</h1>
<div class=card>
  <p>Username: <?= e($u['user']) ?> · Role: <?= e($u['role']) ?> · Email: <?= e($u['email']) ?></p>
</div>
<h2>Public profile</h2>
<!-- VULN: profile fields rendered raw (stored XSS) -->
<div class=card>
  <p>Display name: <?= $mine['display'] ?></p>
  <p>City: <?= $mine['city'] ?></p>
  <p>Bio: <?= $mine['bio'] ?></p>
</div>
<form method=post class=stack>
  <input name=display value="<?= e($mine['display']) ?>" placeholder='display name'>
  <input name=city value="<?= e($mine['city']) ?>" placeholder=city>
  <textarea name=bio placeholder=bio><?= e($mine['bio']) ?></textarea>
  <button class=btn>Save profile</button>
</form>
<?php dsp_footer();
