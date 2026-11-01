// Intentionally vulnerable Kotlin/Android code for demo and CI purposes.
// See examples/safe/UserRepository.kt for the corrected version.
import java.security.MessageDigest
import java.io.ObjectInputStream
import kotlin.random.Random

class UserRepository(private val db: SQLiteDatabase) {

    fun findUser(id: String): Cursor {
        // CWE-89: SQL built with a Kotlin string-template interpolation
        return db.rawQuery("SELECT * FROM users WHERE id = $id", null)
    }

    fun loadSession(input: java.io.InputStream): Any {
        // CWE-502: native Java/Kotlin deserialization on untrusted input
        val ois = ObjectInputStream(input)
        return ois.readObject()
    }

    fun hashPassword(password: String): String {
        // CWE-327: MD5 is not a password hash
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray()).joinToString("")
    }

    fun newSessionToken(): Int {
        // CWE-330: non-cryptographic RNG used for a security token
        val r = Random()
        return r.nextInt()  // session token
    }

    fun runTool(filename: String) {
        // CWE-78: Runtime.exec with a concatenated command string
        Runtime.getRuntime().exec("convert " + filename + " out.png")
    }
}
