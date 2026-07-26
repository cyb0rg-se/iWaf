<?php require __DIR__ . '/lib/common.php';
// NORMAL: product reviews (post + list). VULN: stored XSS (body rendered raw).
$reviews = dsp_json_read('reviews.json');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['body'])) {
    $reviews[] = ['name'=>$_POST['name'] ?? 'anon', 'stars'=>(int)($_POST['stars'] ?? 5),
                  'body'=>$_POST['body'], 'ts'=>date('Y-m-d H:i')];
    dsp_json_write('reviews.json', array_slice($reviews, -30));
    header('Location: /review.php'); exit;
}
dsp_header('Reviews', 'reviews');
?>
<h1>Product Reviews</h1>
<form method=post class=reviewform>
  <input name=name placeholder='your name'>
  <select name=stars><?php for($i=5;$i>=1;$i--) echo "<option>$i</option>"; ?></select>
  <textarea name=body placeholder='write a review'></textarea>
  <button class=btn>Post review</button>
</form>
<ul class=reviews>
<?php foreach (array_reverse($reviews) as $r): ?>
  <li><div class=rhead><b><?= e($r['name']) ?></b> <span class=stars><?= str_repeat('★', max(1,min(5,$r['stars']))) ?></span> <i><?= e($r['ts']) ?></i></div>
  <div class=rbody><?= $r['body'] ?></div></li>
<?php endforeach; ?>
<?php if (!$reviews): ?><li class=empty>No reviews yet — be the first!</li><?php endif; ?>
</ul>
<?php dsp_footer();
