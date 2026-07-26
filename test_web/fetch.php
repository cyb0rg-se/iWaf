<?php require __DIR__ . '/lib/common.php';
// VULN: SSRF — server-side "link preview" of a user URL (SIMULATED; no real request made).
$url = isset($_GET['url']) ? $_GET['url'] : '';
dsp_header('Link Preview');
echo "<h1>Link Preview</h1>";
if ($url !== '') {
    echo "<div class=card><p>Preview of <code>" . e($url) . "</code></p>"
       . "<p class=debug>[server would fetch: file_get_contents(" . e($url) . ")]</p></div>";
} else {
    echo "<form class=stack><input name=url placeholder='https://example.com/page'><button class=btn>Preview</button></form>";
}
dsp_footer();
