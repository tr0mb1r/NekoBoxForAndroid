package io.nekohasekai.sagernet.util

import android.util.Base64
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom

object ProxyAuth {

    @Volatile
    private var current: Pair<String, String>? = null

    @Volatile
    private var currentPort: Int = 0

    @Volatile
    private var currentClashSecret: String? = null

    private val rng = SecureRandom()

    fun generate(): Pair<String, String> {
        val bytes = ByteArray(24).also { rng.nextBytes(it) }
        val user = Base64.encodeToString(bytes.copyOfRange(0, 12), Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
        val pass = Base64.encodeToString(bytes.copyOfRange(12, 24), Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
        val pair = Pair(user, pass)
        current = pair
        return pair
    }

    fun current(): Pair<String, String>? = current

    fun allocatePort(): Int {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { sock ->
            currentPort = sock.localPort
        }
        return currentPort
    }

    fun port(): Int = currentPort

    fun allocateClashSecret(): String {
        val bytes = ByteArray(32).also { rng.nextBytes(it) }
        val secret = Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
        currentClashSecret = secret
        return secret
    }

    fun clashSecret(): String? = currentClashSecret

    fun clear() {
        current = null
        currentPort = 0
        currentClashSecret = null
    }
}
