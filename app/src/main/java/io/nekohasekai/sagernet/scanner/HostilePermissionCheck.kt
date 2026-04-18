package io.nekohasekai.sagernet.scanner

import android.content.pm.PackageManager

/**
 * Layer 5 — permission heuristic.
 *
 * Apps that request `QUERY_ALL_PACKAGES` can enumerate every installed
 * app on the device — a prerequisite for fingerprinting which VPN
 * client the user runs. Declaring the permission alone isn't proof of
 * malicious intent (launchers, security tools, and some legitimate
 * utilities need it), but combined with a Russian package prefix or
 * an embedded tracking SDK it bumps the risk level decisively.
 *
 * Cost: ~1 ms per package (one PackageManager lookup).
 */
object HostilePermissionCheck {

    val BUILTIN_SUSPICIOUS_PERMISSIONS: List<String> = listOf(
        "android.permission.QUERY_ALL_PACKAGES",
    )

    fun check(pm: PackageManager, packageName: String): Boolean {
        return try {
            val info = pm.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS,
            )
            val requested = info.requestedPermissions ?: return false
            val remote = SignatureRegistry.current().suspiciousPermissions
            (BUILTIN_SUSPICIOUS_PERMISSIONS + remote).any { it in requested }
        } catch (_: PackageManager.NameNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }
}
