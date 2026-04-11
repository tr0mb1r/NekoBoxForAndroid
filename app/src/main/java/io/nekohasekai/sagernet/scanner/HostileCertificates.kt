package io.nekohasekai.sagernet.scanner

import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Layer 2 — signing certificate fingerprint.
 *
 * Matches the SHA-256 of any signer certificate against a known set of
 * hostile-publisher fingerprints. Definitive publisher identification
 * that cannot be evaded without re-signing (which breaks Play Store
 * update integrity).
 *
 * **Populating the FINGERPRINTS set**
 *
 * The set starts empty. Actual fingerprints come from:
 *   1. Manually: extract from a real APK via
 *      `keytool -printcert -jarfile app.apk | grep SHA256`
 *   2. Remote signature updates (Task #23) — fetched from the
 *      `hostile-sigs` repo over the VPN tunnel, merged with the
 *      built-in set at app startup.
 *
 * Until then, Layer 2 is effectively a no-op and Layers 1/3/4 carry
 * the detection load. That's fine — Layer 4 (DEX scan) is strictly
 * stronger anyway.
 */
object HostileCertificates {

    /**
     * SHA-256 of signer certs, colon-separated uppercase hex
     * ("A5:12:...:F7"). Populated at build time + merged with remote
     * signature updates at runtime.
     */
    val FINGERPRINTS: MutableSet<String> = mutableSetOf(
        // TODO(#23): seed from the hostile-sigs repo on first release.
        //
        // Example format:
        //   "A5:12:34:56:...:F7"  // Yandex LLC (apps signed under CN=Yandex LLC)
        //   "B3:2F:8A:01:...:D4"  // VK (Mail.ru Group)
        //   "C7:9E:4B:0C:...:12"  // Sberbank
        //   "D1:6A:7F:22:...:88"  // Tinkoff
    )

    @Suppress("DEPRECATION")
    fun check(pm: PackageManager, packageName: String): Boolean {
        if (FINGERPRINTS.isEmpty()) return false

        return try {
            val signatures = if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES,
                )
                info.signingInfo?.apkContentsSigners ?: return false
            } else {
                val info = pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES,
                )
                info.signatures ?: return false
            }

            val md = MessageDigest.getInstance("SHA-256")
            signatures.any { sig ->
                val hash = md.digest(sig.toByteArray())
                val hex = hash.joinToString(":") { "%02X".format(it) }
                hex in FINGERPRINTS
            }
        } catch (_: PackageManager.NameNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }
}
