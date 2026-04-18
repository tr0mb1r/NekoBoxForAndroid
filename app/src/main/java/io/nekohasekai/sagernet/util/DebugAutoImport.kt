package io.nekohasekai.sagernet.util

import android.content.Context
import android.net.VpnService
import android.util.Log
import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.parseProxies

object DebugAutoImport {

    private const val TAG = "DebugAutoImport"

    suspend fun runIfEnabled(context: Context) {
        if (!BuildConfig.DEBUG) return
        val url = BuildConfig.DEBUG_AUTOIMPORT_VLESS
        Log.i(TAG, "runIfEnabled: url.isBlank=${url.isBlank()} autoconnect=${BuildConfig.DEBUG_AUTOCONNECT_VPN}")
        if (url.isBlank()) return

        val existing = SagerDatabase.proxyDao.getAll()
        if (existing.isNotEmpty()) {
            Log.i(TAG, "${existing.size} profile(s) already exist, skipping import")
        } else {
            try {
                val beans = parseProxies(url)
                if (beans.isEmpty()) {
                    Log.w(TAG, "parseProxies returned empty for url=$url")
                    return
                }
                val groupId = DataStore.selectedGroup
                val first = ProfileManager.createProfile(groupId, beans.first())
                for (bean in beans.drop(1)) {
                    ProfileManager.createProfile(groupId, bean)
                }
                DataStore.selectedProxy = first.id
                Log.i(TAG, "imported ${beans.size} profile(s), selected id=${first.id}")
            } catch (t: Throwable) {
                Log.w(TAG, "import failed", t)
                return
            }
        }

        if (BuildConfig.DEBUG_AUTOCONNECT_VPN) {
            try {
                if (VpnService.prepare(context) == null) {
                    SagerNet.startService()
                    Log.i(TAG, "started VPN service")
                } else {
                    Log.w(TAG, "VpnService.prepare() requires user consent — grant via UI once or `adb shell appops set ${context.packageName} ACTIVATE_VPN allow`")
                }
            } catch (t: Throwable) {
                Log.w(TAG, "auto-connect failed", t)
            }
        }
    }
}
