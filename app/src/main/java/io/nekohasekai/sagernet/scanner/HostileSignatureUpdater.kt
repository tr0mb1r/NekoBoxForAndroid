package io.nekohasekai.sagernet.scanner

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import io.nekohasekai.sagernet.database.DataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches a remote signature JSON over the VPN tunnel and merges it
 * into [SignatureRegistry]. The URL comes from
 * `BuildConfig.HOSTILE_SIGS_URL` (configurable per fork, default
 * empty → no-op).
 *
 * Expected shape:
 *
 * ```json
 * {
 *   "version": 3,
 *   "package_prefixes": ["ru.new-thing.", "..."],
 *   "cert_fingerprints": ["A5:12:...:F7"],
 *   "metadata_keys": ["com.new-sdk.API_KEY"],
 *   "provider_authorities": ["com.new-sdk.provider"],
 *   "suspicious_permissions": [],
 *   "class_prefixes": ["com.new-sdk.analytics"]
 * }
 * ```
 *
 * Versioning: the `version` field is an integer that must strictly
 * increase for an update to be accepted. Clients ignore updates
 * with an equal or lower version. Rolling back a published signature
 * requires publishing a new version with the entry removed.
 *
 * Failure semantics: all errors are swallowed. A network hiccup, a
 * 404, a parse error, etc., leave the previous state in place. The
 * scanner still works with built-in signatures regardless.
 */
object HostileSignatureUpdater {

    private const val TAG = "HostileSigUpdater"
    private const val TIMEOUT_MS = 10_000
    private const val MAX_BODY_BYTES = 64 * 1024

    private val gson = Gson()

    /**
     * One-shot fetch. Call after the VPN is connected so traffic
     * routes through the tunnel. Silent failure on any error.
     *
     * Returns true if an update was downloaded and applied, false
     * otherwise (stale, empty URL, network error, parse error).
     */
    suspend fun fetchAndApply(context: Context): Boolean = withContext(Dispatchers.IO) {
        val urlString = DataStore.hostileSigsUrl.orEmpty().trim()
        if (urlString.isBlank()) {
            Log.d(TAG, "hostileSigsUrl is empty, skipping")
            return@withContext false
        }

        var connection: HttpURLConnection? = null
        try {
            connection = (URL(urlString).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                setRequestProperty("User-Agent", "NekoBox-Hardening-SigUpdater/1")
                setRequestProperty("Accept", "application/json")
            }
            val code = connection.responseCode
            if (code !in 200..299) {
                Log.w(TAG, "fetch failed: HTTP $code")
                return@withContext false
            }
            val declared = connection.contentLength
            if (declared in 1..MAX_BODY_BYTES || declared == -1) {
                val text = connection.inputStream.use { input ->
                    val buf = ByteArray(MAX_BODY_BYTES + 1)
                    var total = 0
                    while (total < buf.size) {
                        val n = input.read(buf, total, buf.size - total)
                        if (n <= 0) break
                        total += n
                    }
                    if (total > MAX_BODY_BYTES) {
                        Log.w(TAG, "body exceeded $MAX_BODY_BYTES bytes, rejected")
                        return@withContext false
                    }
                    String(buf, 0, total, Charsets.UTF_8)
                }
                val parsed = runCatching {
                    gson.fromJson(text, SignatureRegistry.RemoteSignatures::class.java)
                }.getOrNull()
                if (parsed == null) {
                    Log.w(TAG, "failed to parse signatures JSON")
                    return@withContext false
                }
                val applied = SignatureRegistry.applyRemote(context, parsed)
                Log.i(
                    TAG,
                    if (applied) "applied v${parsed.version} " +
                        "(${parsed.packagePrefixes.size} pkg, ${parsed.classPrefixes.size} dex)"
                    else "skipped v${parsed.version} " +
                        "(current=${SignatureRegistry.currentVersion(context)})",
                )
                return@withContext applied
            } else {
                Log.w(TAG, "declared body too large: $declared bytes")
                return@withContext false
            }
        } catch (t: Throwable) {
            Log.w(TAG, "fetch failed: ${t.message}")
            return@withContext false
        } finally {
            try { connection?.disconnect() } catch (_: Exception) {}
        }
    }
}
