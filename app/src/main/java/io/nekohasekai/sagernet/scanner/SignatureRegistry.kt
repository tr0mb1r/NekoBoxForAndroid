package io.nekohasekai.sagernet.scanner

import android.content.Context
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName

/**
 * Mutable signature registry. Each detection layer combines its
 * built-in (hardcoded) list with whatever lives here, so remote
 * updates can extend detection without shipping a new APK.
 *
 * The registry is persisted in SharedPreferences as a single JSON
 * blob. It's loaded lazily on first access and invalidated when
 * [HostileSignatureUpdater] pushes a new version.
 *
 * Thread-safe via @Volatile + synchronized write paths.
 */
object SignatureRegistry {

    private const val PREFS_NAME = "hostile_scan_signatures"
    private const val KEY_REMOTE_JSON = "remote_json"
    private const val KEY_REMOTE_VERSION = "remote_version"

    data class RemoteSignatures(
        @SerializedName("version") val version: Int = 0,
        @SerializedName("package_prefixes") val packagePrefixes: List<String> = emptyList(),
        @SerializedName("cert_fingerprints") val certFingerprints: List<String> = emptyList(),
        @SerializedName("metadata_keys") val metadataKeys: List<String> = emptyList(),
        @SerializedName("provider_authorities") val providerAuthorities: List<String> = emptyList(),
        @SerializedName("suspicious_permissions") val suspiciousPermissions: List<String> = emptyList(),
        @SerializedName("class_prefixes") val classPrefixes: List<String> = emptyList(),
    )

    @Volatile
    private var cached: RemoteSignatures = RemoteSignatures()

    @Volatile
    private var loaded: Boolean = false

    private val gson = Gson()

    /**
     * Read-only accessor for the currently-loaded remote signatures.
     * Returns an empty set if [load] hasn't run yet, which means
     * layers fall back to their built-in lists only — the safe default.
     */
    fun current(): RemoteSignatures = cached

    fun load(context: Context): RemoteSignatures {
        if (loaded) return cached
        synchronized(this) {
            if (loaded) return cached
            val json = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_REMOTE_JSON, null)
            cached = if (json.isNullOrBlank()) {
                RemoteSignatures()
            } else {
                runCatching { gson.fromJson(json, RemoteSignatures::class.java) }
                    .getOrElse { RemoteSignatures() }
            }
            loaded = true
        }
        return cached
    }

    /**
     * Merge a newly-fetched remote signature set if its [version] is
     * strictly greater than the stored version. Returns true if the
     * update was applied, false if it was rejected (stale/same/invalid).
     */
    @Synchronized
    fun applyRemote(context: Context, incoming: RemoteSignatures): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val currentVersion = prefs.getInt(KEY_REMOTE_VERSION, 0)
        if (incoming.version <= currentVersion) return false

        val serialized = gson.toJson(incoming)
        prefs.edit()
            .putString(KEY_REMOTE_JSON, serialized)
            .putInt(KEY_REMOTE_VERSION, incoming.version)
            .apply()

        cached = incoming
        loaded = true
        return true
    }

    /** Current remote-download version number (0 if never updated). */
    fun currentVersion(context: Context): Int =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getInt(KEY_REMOTE_VERSION, 0)
}
