<?php require __DIR__ . '/lib/common.php';
// NORMAL: contact form -> messages.json. VULN: subject used in a (simulated) mail header; stored msg.
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $subject = $_POST['subject'] ?? '';
    $body    = $_POST['body'] ?? '';
    $email   = $_POST['email'] ?? '';
    $msgs = dsp_json_read('messages.json');
    $msgs[] = ['email'=>$email, 'subject'=>$subject, 'body'=>$body, 'ts'=>date('Y-m-d H:i')];
    dsp_json_write('messages.json', array_slice($msgs,-30));
    // simulated mail header (header injection sink — echoed, not sent)
    $hdr = "Subject: $subject\r\nFrom: $email";
    $msg = "<span class=ok>Thanks! Your message was received.</span>"
         . "<p class=debug>[mail headers: " . e($hdr) . "]</p>";
}
dsp_header('Contact', 'contact');
echo "<h1>Contact us</h1>"; dsp_flash($msg);
echo "<form method=post class=stack><input name=email placeholder='your email'>"
   . "<input name=subject placeholder=subject>"
   . "<textarea name=body placeholder='your message'></textarea>"
   . "<button class=btn>Send</button></form>";
dsp_footer();
