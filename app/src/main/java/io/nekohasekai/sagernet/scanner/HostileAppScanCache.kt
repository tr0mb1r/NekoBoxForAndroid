package io.nekohasekai.sagernet.scanner

import android.content.Context
import android.content.pm.PackageManager
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * SharedPreferences-backed cache for scan results, keyed by package
 * name. Stores `lastUpdateTime` from the target APK's `PackageInfo`
 * so upgrades invalidate the cache automatically — we re-scan only
 * when the APK bytes actually changed.
 *
 * Kept deliberately small: a single JSON blob holding the whole map.
 * At ~100 installed apps with a few hundred bytes per entry, the
 * total cache is well under 64 KB.
 *
 * Access is process-safe via SharedPreferences' internal locking but
 * not across processes — the scanner only runs in the main process.
 */
object HostileAppScanCache {

    private const val PREFS_NAME = "hostile_scan_cache"
    private const val KEY_ENTRIES = "entries"

    private val gson = Gson()
    private val type = object : TypeToken<Map<String, CachedScanResult>>() {}.type

    data class CachedScanResult(
        val packageName: String,
        val lastUpdateTime: Long,
        val riskLevel: RiskLevel,
        val reasons: List<String>,
        val dexSdks: List<String>,
        val scannedAt: Long,
    )

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun loadAll(context: Context): Map<String, CachedScanResult> {
        val raw = prefs(context).getString(KEY_ENTRIES, null) ?: return emptyMap()
        return try {
            gson.fromJson<Map<String, CachedScanResult>>(raw, type) ?: emptyMap()
        } catch (_: Exception) {
            emptyMap()
        }
    }

    @Synchronized
    private fun saveAll(context: Context, entries: Map<String, CachedScanResult>) {
        prefs(context).edit().putString(KEY_ENTRIES, gson.toJson(entries)).apply()
    }

    /**
     * Return the cached result for [packageName] only if it's still
     * current (cache's stored lastUpdateTime matches the installed
     * APK's current lastUpdateTime). Returns null otherwise — caller
     * should re-scan.
     */
    fun getIfCurrent(context: Context, packageName: String): CachedScanResult? {
        val entry = loadAll(context)[packageName] ?: return null
        val currentMtime = try {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(packageName, 0).lastUpdateTime
        } catch (_: PackageManager.NameNotFoundException) {
            return null
        } catch (_: Exception) {
            return null
        }
        return if (entry.lastUpdateTime == currentMtime) entry else null
    }

    fun put(context: Context, entry: CachedScanResult) {
        val entries = loadAll(context).toMutableMap()
        entries[entry.packageName] = entry
        saveAll(context, entries)
    }

    fun putAll(context: Context, newEntries: List<CachedScanResult>) {
        val entries = loadAll(context).toMutableMap()
        for (e in newEntries) entries[e.packageName] = e
        saveAll(context, entries)
    }

    /** Evict a single package's entry (on install/update/uninstall). */
    fun evict(context: Context, packageName: String) {
        val entries = loadAll(context).toMutableMap()
        if (entries.remove(packageName) != null) {
            saveAll(context, entries)
        }
    }

    fun clear(context: Context) {
        prefs(context).edit().remove(KEY_ENTRIES).apply()
    }

    /** Convert a ScanResult into the cache's wire format. */
    fun fromScanResult(
        packageManager: PackageManager,
        result: ScanResult,
    ): CachedScanResult {
        val lastUpdateTime = try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(result.packageName, 0).lastUpdateTime
        } catch (_: Exception) {
            0L
        }
        return CachedScanResult(
            packageName = result.packageName,
            lastUpdateTime = lastUpdateTime,
            riskLevel = result.riskLevel,
            reasons = result.reasons,
            dexSdks = result.dexResult?.matchedSdks.orEmpty(),
            scannedAt = System.currentTimeMillis(),
        )
    }
}
