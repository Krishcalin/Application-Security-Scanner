import java.io.*;
import java.sql.*;
import java.net.*;
import java.security.*;
import java.util.Random;
import javax.servlet.http.*;
import javax.xml.parsers.*;

/**
 * Intentionally vulnerable Java class used to verify scanner detection.
 * DO NOT use any of these patterns in production code.
 */
public class VulnerableApp extends HttpServlet {

    // CRED-001: Hardcoded credential
    private static final String password = "s3cr3tP@ssw0rd";
    private static final String apiKey = "AIzaSyD-FAKE-KEY-12345";

    // SQLI-001 / SQLI-002: SQL injection via string concatenation
    public void unsafeSQLQuery(Connection conn, String userInput) throws Exception {
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        conn.createStatement().executeQuery(query);
    }

    // CMDI-001: Command injection via Runtime.exec()
    public void unsafeExec(String userInput) throws Exception {
        Runtime.getRuntime().exec("ping " + userInput);
    }

    // CMDI-002: ProcessBuilder with dynamic arguments
    public void unsafeProcessBuilder(String userInput) throws Exception {
        new ProcessBuilder("sh", "-c", userInput).start();
    }

    // DESER-001: Unsafe ObjectInputStream
    public Object unsafeDeserialize(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // DESER-002: Custom readObject gadget endpoint
    private void readObject(ObjectInputStream ois) throws Exception {
        ois.defaultReadObject();
    }

    // DESER-003: XMLDecoder RCE
    public void unsafeXMLDecoder(InputStream input) {
        XMLDecoder decoder = new XMLDecoder(input);
        decoder.readObject();
    }

    // CRYPTO-001: MD5 usage
    public byte[] unsafeMD5(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes());
    }

    // CRYPTO-002: SHA-1 usage
    public byte[] unsafeSHA1(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data.getBytes());
    }

    // CRYPTO-003: DES cipher
    public void unsafeDES() throws Exception {
        javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // CRYPTO-004: ECB mode
    public void unsafeECB() throws Exception {
        javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // CRYPTO-005: java.util.Random (not cryptographically secure)
    public int unsafeRandom() {
        Random rng = new Random();
        return rng.nextInt();
    }

    // XXE-001: DocumentBuilderFactory without XXE protection
    public void unsafeXMLParse(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(input);
    }

    // PATH-001: Path traversal via request parameter
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        File file = new File(request.getParameter("filename"));

        // XSS-001: Unencoded output
        PrintWriter out = response.getWriter();
        out.println(request.getParameter("userInput"));

        // REDIR-001: Open redirect
        response.sendRedirect(request.getParameter("url"));

        // SSRF-001: SSRF via user-supplied URL
        URL url = new URL(request.getParameter("target"));
        url.openConnection();

        // LOG-001: Log injection
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger("app");
        logger.info(request.getParameter("msg"));
    }
}
