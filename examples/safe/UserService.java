// Hardened version of examples/vulnerable/UserService.java.
import java.sql.PreparedStatement;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class UserService {

    public org.w3c.dom.Document parseUpload(java.io.InputStream xml) throws Exception {
        // Disabling DOCTYPE declarations rules out entity-expansion attacks.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return dbf.newDocumentBuilder().parse(xml);
    }

    public ResultSet findUser(Connection conn, String id) throws Exception {
        // PreparedStatement with a bound parameter: no concatenation at all.
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, id);
        return stmt.executeQuery();
    }

    public void convert(String filename) throws Exception {
        // ProcessBuilder with a separate argument list: no shell involved.
        new ProcessBuilder("convert", filename, "out.png").start();
    }

    public Object loadSession(java.io.InputStream is) throws Exception {
        // Deserialize into a known, safe schema instead of native Java objects.
        return new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(is, SessionData.class);
    }

    public String hashPassword(String password) {
        // BCrypt is a slow, salted KDF -- appropriate for passwords.
        return new BCryptPasswordEncoder().encode(password);
    }
}
