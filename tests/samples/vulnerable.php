<?php
/**
 * Intentionally vulnerable PHP file used to verify scanner detection.
 * DO NOT use any of these patterns in production code.
 */

// PHP-CRED-001: Hardcoded credentials
$db_password = "s3cr3tP@ssw0rd";
$api_key = "AIzaSyD-FAKE-KEY-12345";

// PHP-SQLI-003: Deprecated mysql_* usage
$conn = mysql_connect("localhost", "root", $db_password);
mysql_select_db("app");

// PHP-SQLI-001 + PHP-SQLI-002: SQL injection via superglobal concatenation
$id   = $_GET['id'];
$name = $_POST['name'];
$rows = mysql_query("SELECT * FROM users WHERE id = " . $id);
$rows2 = mysql_query("SELECT * FROM users WHERE name = '" . $name . "'");

// PHP-CRED-002: Hardcoded PDO password
$pdo = new PDO("mysql:host=localhost;dbname=app", "root", "plaintextpassword");

// PHP-CMDI-001: Command injection via superglobal
$host = $_GET['host'];
system("ping -c 1 " . $host);
exec("nslookup " . $_GET['domain']);
passthru("whois " . $_REQUEST['query']);

// PHP-CMDI-002: Backtick operator with user input
$output = `traceroute {$_GET['target']}`;

// PHP-RCE-001: eval() with user-supplied input
eval($_POST['code']);

// PHP-RCE-002: preg_replace with /e modifier
$result = preg_replace('/(.*)/e', $_POST['replace'], $subject);

// PHP-RCE-003: assert() with string input
assert($_GET['assertion']);

// PHP-RCE-004: Variable function call from user input
$func = $_GET['func'];
$func();

// PHP-LFI-001: Local/Remote File Inclusion
include($_GET['page']);
require($_GET['template']);
include_once($_POST['module'] . ".php");

// PHP-LFI-002: file_get_contents with user path
$content = file_get_contents($_GET['file']);
readfile($_GET['download']);

// PHP-XSS-001: Reflected XSS – superglobal echoed unencoded
echo $_GET['search'];
echo "<h1>Welcome " . $_POST['username'] . "</h1>";
print $_COOKIE['theme'];

// PHP-DESER-001: Unsafe unserialize with user input
$obj = unserialize($_COOKIE['cart']);
$obj2 = unserialize(base64_decode($_GET['data']));

// PHP-CRYPTO-001/002/003: Weak cryptographic functions
$hash     = md5($_POST['password']);
$token    = sha1($_POST['email'] . time());
$nonce    = rand(100000, 999999);
$token2   = mt_rand();

// PHP-CRYPTO-004: Deprecated mcrypt
$encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $plaintext, MCRYPT_MODE_ECB);

// PHP-XXE-001: SimpleXML without XXE hardening
$xml  = simplexml_load_string($_POST['xml']);
$xml2 = simplexml_load_file($_GET['xmlfile']);

// PHP-XXE-002: DOMDocument without XXE hardening
$dom = new DOMDocument();
$dom->loadXML($_POST['xmldata']);
$dom->load($_GET['xmlfile']);

// PHP-SSRF-001: cURL with user-supplied URL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET['url']);
curl_exec($ch);

// PHP-SSRF-002: file_get_contents with user URL
$response = file_get_contents($_GET['endpoint']);

// PHP-REDIR-001: Open redirect
header('Location: ' . $_GET['redirect']);

// PHP-SESS-001: session_start without secure config
session_start();

// PHP-SESS-002: Session fixation
session_id($_GET['sid']);

// PHP-TYPE-001: Loose comparison in auth check
if ($_POST['token'] == $stored_token) {
    // grant access
}
if ($_GET['admin'] == true) {
    // admin panel
}

// PHP-INFO-001: phpinfo() exposure
phpinfo();

// PHP-INFO-002: display_errors enabled at runtime
ini_set('display_errors', '1');

// PHP-SHELL-001: Webshell pattern
eval(base64_decode($_POST['payload']));
eval(gzinflate(base64_decode($_POST['c'])));

// PHP-SHELL-002: create_function (deprecated RCE vector)
$fn = create_function('$x', $_GET['body']);
$fn(42);
