package io.nekohasekai.sagernet.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Manifest-registered receiver for package install/update/uninstall.
 *
 * `ACTION_PACKAGE_ADDED`, `ACTION_PACKAGE_REPLACED`, and
 * `ACTION_PACKAGE_REMOVED` are explicitly exempted from Android 8+
 * implicit-broadcast restrictions when the intent has a `package:`
 * data scheme — so manifest registration is allowed here.
 *
 * On each event we evict the affected package from the cache.
 * Re-scanning of the new APK happens the next time the scanner runs
 * (VPN start, WorkManager tick, or user-triggered refresh).
 */
class HostileAppScanReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val pkg = intent.data?.schemeSpecificPart ?: return

        when (action) {
            Intent.ACTION_PACKAGE_ADDED,
            Intent.ACTION_PACKAGE_REPLACED,
            Intent.ACTION_PACKAGE_REMOVED -> {
                HostileAppScanCache.evict(context, pkg)
                Log.i(TAG, "evicted cache for $pkg (action=$action)")
            }
        }
    }

    companion object {
        private const val TAG = "HostileAppScanReceiver"
    }
}
