// Hardened version of examples/vulnerable/UserRepository.kt.
import java.security.SecureRandom
import com.google.gson.Gson

class UserRepository(private val db: SQLiteDatabase) {

    fun findUser(id: String): Cursor {
        // Parameterized query: selectionArgs, not string interpolation.
        return db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))
    }

    fun loadSession(input: java.io.InputStream): SessionData {
        // Deserialize into a known, safe schema instead of native objects.
        return Gson().fromJson(input.reader(), SessionData::class.java)
    }

    fun hashPassword(password: String): String {
        // A dedicated password-hashing library (BCrypt) handles salting
        // and a deliberately slow KDF correctly.
        return org.mindrot.jbcrypt.BCrypt.hashpw(password, org.mindrot.jbcrypt.BCrypt.gensalt())
    }

    fun newSessionToken(): String {
        // SecureRandom is seeded from the OS CSPRNG.
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun runTool(filename: String) {
        // ProcessBuilder with a separate argument list: no shell involved.
        ProcessBuilder("convert", filename, "out.png").start()
    }
}
