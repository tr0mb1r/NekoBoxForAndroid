package io.nekohasekai.sagernet.scanner

import android.content.Context
import android.util.Log

/**
 * Per-VPN-session holder for the scanner's exclude-package list.
 *
 * Populated once by [BoxInstance.init] before [ConfigBuilder] runs,
 * read by [ConfigBuilder] when it builds the tun inbound, and cleared
 * by [BoxInstance.close] when the VPN stops.
 *
 * Why this exists: `ConfigBuilder.buildConfig()` is a non-suspend
 * function called from a suspend context, and the scanner's
 * `quickScan()` is itself suspend. Rather than plumbing `runBlocking`
 * into the config builder (ugly) or threading an extra parameter
 * through the top-level build function (invasive), we stash the
 * pre-computed exclude list in a singleton that the builder reads
 * lazily.
 */
object HostileScanSession {

    private const val TAG = "HostileScanSession"

    @Volatile
    private var excludeList: List<String> = emptyList()

    @Volatile
    private var lastResultCount: Int = 0

    /**
     * Run [HostileAppScanner.quickScan] and stash the resulting
     * exclude list. Called from [BoxInstance.init] on the IO
     * dispatcher before [ConfigBuilder] runs.
     */
    suspend fun refresh(context: Context) {
        try {
            val scanner = HostileAppScanner(context)
            val results = scanner.quickScan()
            val autoExclude = scanner.toExcludeList(results)
            val userOptOut = HostileScanPrefs.userOptOut(context)
            val list = autoExclude.filterNot { it in userOptOut }
            excludeList = list
            lastResultCount = results.size
            Log.i(
                TAG,
                "quickScan: flagged=${results.size}, auto=${autoExclude.size}, " +
                    "optOut=${userOptOut.size}, excluding=${list.size}",
            )
        } catch (t: Throwable) {
            Log.w(TAG, "quickScan failed: ${t.message}")
            excludeList = emptyList()
            lastResultCount = 0
        }
    }

    /** Current exclude list, or empty if [refresh] hasn't run. */
    fun excludeList(): List<String> = excludeList

    fun clear() {
        excludeList = emptyList()
        lastResultCount = 0
    }
}
