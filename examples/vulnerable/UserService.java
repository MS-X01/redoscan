// Intentionally vulnerable Java code for demo and CI purposes.
// See examples/safe/UserService.java for the corrected version.
import java.security.MessageDigest;
import java.sql.Statement;
import java.io.ObjectInputStream;
import javax.xml.parsers.DocumentBuilderFactory;

public class UserService {

    public org.w3c.dom.Document parseUpload(java.io.InputStream xml) throws Exception {
        // CWE-776: default factory settings allow external entity expansion
        // ("billion laughs") on untrusted XML.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(xml);
    }

    public ResultSet findUser(Connection conn, String id) throws Exception {
        // CWE-89: SQL built by concatenating a Statement query string
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public void convert(String filename) throws Exception {
        // CWE-78: Runtime.exec with a concatenated command string
        Runtime.getRuntime().exec("convert " + filename + " out.png");
    }

    public Object loadSession(java.io.InputStream is) throws Exception {
        // CWE-502: native Java deserialization on untrusted input
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }

    public byte[] hashPassword(String password) throws Exception {
        // CWE-327: MD5 is not a password hash
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}
