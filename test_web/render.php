<?php require __DIR__ . '/lib/common.php';
// VULN: SSTI — 'tpl' rendered by a (simulated) template engine. NORMAL: greeting card preview.
$tpl  = isset($_GET['tpl'])  ? $_GET['tpl']  : 'Hello {{name}}, welcome to {{shop}}!';
$name = isset($_GET['name']) ? $_GET['name'] : 'friend';
$out  = str_replace(['{{name}}','{{shop}}'], [e($name),'DemoShop'], e($tpl));
dsp_header('Card Preview');
echo "<h1>Greeting Card Preview</h1>";
echo "<div class=cardpreview>" . $out . "</div>";
echo "<p class=debug>[template engine would render raw: " . e($tpl) . "]</p>";
echo "<form class=stack><input name=name placeholder=name value='" . e($name) . "'>"
   . "<input name=tpl value='" . e($tpl) . "'><button class=btn>Preview</button></form>";
dsp_footer();
