package io.nekohasekai.sagernet.scanner

import android.content.Context

/**
 * User-override persistence for the hostile-app scanner.
 *
 * By default, anything the scanner flags as MEDIUM or higher gets
 * auto-excluded from the VPN tunnel. Users can override individual
 * apps via the [ScannerFragment] UI — those package names land here.
 *
 * On VPN start, [HostileScanSession.refresh] subtracts this set from
 * the scanner's exclude list, so user opt-outs take precedence.
 */
object HostileScanPrefs {

    private const val PREFS_NAME = "hostile_scan_prefs"
    private const val KEY_USER_OPT_OUT = "user_opt_out_packages"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Packages the user has explicitly opted OUT of auto-exclusion. */
    fun userOptOut(context: Context): Set<String> =
        prefs(context).getStringSet(KEY_USER_OPT_OUT, emptySet())?.toSet().orEmpty()

    fun setUserOptOut(context: Context, packages: Set<String>) {
        prefs(context).edit().putStringSet(KEY_USER_OPT_OUT, packages).apply()
    }
}
