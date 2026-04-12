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
     * Built-in SHA-256 of signer certs, colon-separated uppercase hex
     * ("A5:12:...:F7"). Combined with [SignatureRegistry.current]
     * remote fingerprints at check time.
     *
     * The built-in set starts empty — real Yandex/VK/Sber/Tinkoff
     * hashes come via remote signature updates (the fork owner can
     * push JSON to the `hostile-sigs` repo and clients pick it up
     * on the next VPN start).
     */
    val BUILTIN_FINGERPRINTS: Set<String> = emptySet()

    @Suppress("DEPRECATION")
    fun check(pm: PackageManager, packageName: String): Boolean {
        val remote = SignatureRegistry.current().certFingerprints
        if (BUILTIN_FINGERPRINTS.isEmpty() && remote.isEmpty()) return false
        val combined = BUILTIN_FINGERPRINTS + remote

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
            // Normalize the combined set to lowercase-no-colons so we
            // match regardless of whether the feed uses "aa:bb" or
            // "aabb" or "AA:BB" format.
            val normalized = combined.mapTo(mutableSetOf()) {
                it.replace(":", "").lowercase()
            }
            signatures.any { sig ->
                val hash = md.digest(sig.toByteArray())
                val hex = hash.joinToString("") { "%02x".format(it) }
                hex in normalized
            }
        } catch (_: PackageManager.NameNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }
}
