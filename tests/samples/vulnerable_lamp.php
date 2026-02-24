<?php
/**
 * vulnerable_lamp.php
 * Intentionally vulnerable LAMP-stack PHP application for scanner testing.
 * DO NOT deploy this file — it exists solely as a scan target.
 */

// --- LAMP-PHP-015: phpinfo() call in production ---
phpinfo();

// -------------------------------------------------------
// Database connection using deprecated mysql_* functions
// -------------------------------------------------------
// --- LAMP-PHP-002: Deprecated mysql_* functions ---
$conn = mysql_connect("localhost", "root", "password");
mysql_select_db("myapp", $conn);

// --- LAMP-PHP-001: mysqli_query with variable interpolation (SQL injection) ---
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");

// Direct mysqli concatenation
$username = $_POST['username'];
$query = "SELECT * FROM users WHERE username = '" . $username . "'";
$result2 = mysqli_query($conn, $query);

// -------------------------------------------------------
// Variable injection
// -------------------------------------------------------
// --- LAMP-PHP-003: extract() with superglobal ---
extract($_POST);
extract($_GET);

// --- LAMP-PHP-004: parse_str without second argument ---
parse_str($_SERVER['QUERY_STRING']);

// -------------------------------------------------------
// Email header injection
// -------------------------------------------------------
// --- LAMP-PHP-005: mail() with user input ---
$to = $_POST['email'];
$subject = $_POST['subject'];
$message = $_POST['message'];
mail($to, $subject, $message);

// -------------------------------------------------------
// Session fixation
// -------------------------------------------------------
session_start();
// --- LAMP-PHP-006: session_id() from GET parameter ---
session_id($_GET['sessid']);

// -------------------------------------------------------
// File upload without validation
// -------------------------------------------------------
// --- LAMP-PHP-007: move_uploaded_file without validation ---
$uploadDir = '/var/www/html/uploads/';
$uploadFile = $uploadDir . basename($_FILES['userfile']['name']);
move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadFile);

// -------------------------------------------------------
// Weak randomness for security tokens
// -------------------------------------------------------
// --- LAMP-PHP-008: mt_rand() for token generation ---
$token = md5(mt_rand());
$resetToken = mt_rand(100000, 999999);
$csrfToken = sha1(mt_rand());

// -------------------------------------------------------
// PHP object injection
// -------------------------------------------------------
// --- LAMP-PHP-009: unserialize() with cookie data ---
$userData = unserialize($_COOKIE['user_data']);
$cartData = unserialize($_GET['cart']);

// -------------------------------------------------------
// LDAP injection
// -------------------------------------------------------
// --- LAMP-PHP-010: ldap_search with user input ---
$ldap = ldap_connect("ldap://localhost");
$filter = "(uid=" . $_POST['username'] . ")";
$result = ldap_search($ldap, "dc=example,dc=com", $filter);

// Actually using the superglobal directly:
$result2 = ldap_search($ldap, "dc=example,dc=com", $_GET['filter']);

// -------------------------------------------------------
// XPath injection
// -------------------------------------------------------
// --- LAMP-PHP-011: XPath query with user input ---
$xml = simplexml_load_file('users.xml');
$xpath_query = "//user[@id='" . $_GET['id'] . "']";
$result = $xml->xpath($xpath_query);

$dom = new DOMDocument();
$dom->load('config.xml');
$xp = new DOMXPath($dom);
$nodes = $xp->query("//setting[@name='" . $_REQUEST['setting'] . "']");

// -------------------------------------------------------
// Webshell pattern
// -------------------------------------------------------
// --- LAMP-PHP-012: preg_replace /e modifier (code execution) ---
$input = $_GET['data'];
$output = preg_replace("/(.*)/e", $input, "test");

// --- PHP-SHELL-001: eval(base64_decode()) webshell pattern ---
eval(base64_decode($_POST['payload']));

// -------------------------------------------------------
// Path traversal / file operations with user input
// -------------------------------------------------------
// --- LAMP-PHP-013: fopen with user-controlled path ---
$filename = $_GET['file'];
$handle = fopen($filename, 'r');
$contents = file_get_contents($_REQUEST['path']);
readfile($_POST['filename']);

// --- PHP-LFI-001: include() with user-supplied path ---
include($_GET['page']);
require($_POST['template']);

// -------------------------------------------------------
// Type juggling
// -------------------------------------------------------
// --- LAMP-PHP-014: Loose comparison for security check ---
$token = $_GET['token'];
if ($token == 0) {
    // bypass: any non-numeric string equals 0 in PHP 7
    echo "Access granted";
}

$hash = md5($_POST['password']);
if ($hash == "0e462097431906509019562988736854") {
    // magic hash bypass: PHP treats 0e... as scientific notation
    echo "Hash match";
}

// -------------------------------------------------------
// Insecure cookie without flags
// -------------------------------------------------------
// --- LAMP-PHP-012 (setcookie without secure/httponly) ---
setcookie("session", $token, time() + 3600, "/");
setcookie("user", $username, time() + 86400);

// -------------------------------------------------------
// SQL injection via raw mysql query
// -------------------------------------------------------
// --- PHP-SQLI-001: Raw SQL with $_GET parameter ---
$id = $_GET['id'];
$sql = "SELECT * FROM products WHERE id = " . $id;
$result = $conn->query($sql);

// -------------------------------------------------------
// Command injection
// -------------------------------------------------------
// --- PHP-CMDI-001: shell_exec with user input ---
$host = $_GET['host'];
$output = shell_exec("ping -c 1 " . $host);

// --- PHP-CMDI-001: system() with user input ---
system("nslookup " . $_REQUEST['domain']);

// -------------------------------------------------------
// XSS
// -------------------------------------------------------
// --- PHP-XSS-001: echo $_GET directly ---
echo "<div>Hello, " . $_GET['name'] . "</div>";

// -------------------------------------------------------
// Hardcoded credentials
// -------------------------------------------------------
// --- PHP-CRED-001: Hardcoded database password ---
$db_password = "SuperSecret123";
$api_key = "sk-hardcoded-api-key-12345";

// -------------------------------------------------------
// Insecure deserialization
// -------------------------------------------------------
// --- PHP-DESER-001: unserialize() with GET param ---
$obj = unserialize($_GET['data']);

?>
