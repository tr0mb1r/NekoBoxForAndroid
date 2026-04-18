package io.nekohasekai.sagernet.scanner

import android.content.Context
import android.content.pm.PackageManager
import java.util.zip.ZipFile

/**
 * Layer 4 — DEX class prefix scan. The key innovation.
 *
 * Scans the APK's compiled bytecode for Russian SDK class prefixes.
 * Catches ANY app embedding these SDKs regardless of package name,
 * signing cert, or manifest config — including third-party apps that
 * bundle Yandex AppMetrica, MyTracker, VK SDK, etc. as a dependency.
 *
 * Cost: ~20-80 ms per APK depending on size. Run on Dispatchers.IO.
 *
 * Two scan strategies:
 * 1. Primary: `dalvik.system.DexFile(apkPath).entries()` — iterates the
 *    class descriptor table directly. Fast, but the API is deprecated
 *    in newer Android versions and may fail silently.
 * 2. Fallback: read `classes*.dex` entries out of the APK ZIP as raw
 *    bytes, convert to ISO_8859_1 string, substring-match the
 *    `Lio/appmetrica/...` descriptors. Slower but works on every API.
 */
object HostileDexScanner {

    /**
     * Class descriptor prefixes that indicate a Russian tracking SDK is
     * compiled into the app. These exist in the DEX bytecode regardless
     * of how (or whether) the SDK is initialized by the app's code.
     */
    val BUILTIN_CLASS_PREFIXES: List<String> = listOf(
        // === Tier 1: analytics that phone home to Russian servers ===
        "io.appmetrica.analytics",   // Yandex AppMetrica (current)
        "com.yandex.metrica",        // Yandex Metrica (legacy package)
        "com.my.tracker",            // MyTracker (Mail.ru, forced RU servers since 2023)
        "com.my.target",             // myTarget (VK ad network)
        "com.yandex.mobile.ads",     // Yandex Ads SDK
        "com.yandex.mapkit",         // Yandex Maps SDK (device-data collector)
        "com.yandex.runtime",        // Yandex runtime (paired with mapkit)

        // === Tier 2: VK / Mail.ru ecosystem SDKs ===
        "com.vk.api",
        "com.vk.sdk",
        "com.vk.auth",
        "com.vk.superapp",
        "ru.ok.android.sdk",         // OK.ru SDK
        "ru.mail.auth",              // Mail.ru auth
        "ru.mail.sdk",               // Mail.ru SDK
        "ru.mail.libnotify",         // Top.Mail.ru push

        // === Tier 3: payment / government SDKs ===
        "ru.sberbank.sdk",
        "ru.sber.sdk",
        "ru.nspk.mirpay",            // Mir Pay
        "ru.rtlabs.mobile",          // Gosuslugi auth

        // === Tier 4: known VPN-detection behavior ===
        "com.kaspersky.components",
        "ru.tinkoff.core.security",
        "ru.sberbank.mobile.core.security",
    )

    /**
     * Built-in list combined with any remote signature updates.
     * Recomputed on each call — the remote list is small (~tens of
     * entries) and [SignatureRegistry.current] is a plain volatile
     * read, so the overhead per scan is negligible.
     */
    private fun activePrefixes(): List<String> {
        val remote = SignatureRegistry.current().classPrefixes
        return if (remote.isEmpty()) BUILTIN_CLASS_PREFIXES
        else BUILTIN_CLASS_PREFIXES + remote
    }

    fun scan(context: Context, packageName: String): DexScanResult {
        val apkPath = try {
            context.packageManager.getApplicationInfo(packageName, 0).sourceDir
        } catch (_: PackageManager.NameNotFoundException) {
            return DexScanResult(packageName, false, emptyList(), "package not found")
        } catch (e: Exception) {
            return DexScanResult(packageName, false, emptyList(), e.message)
        }

        // Try DexFile first, fall back to ZIP substring scan.
        return scanViaDexFile(apkPath, packageName) ?: scanViaZip(apkPath, packageName)
    }

    private fun scanViaDexFile(apkPath: String, packageName: String): DexScanResult? {
        val matched = linkedSetOf<String>()
        return try {
            @Suppress("DEPRECATION")
            val dexFile = dalvik.system.DexFile(apkPath)
            try {
                val entries = dexFile.entries()
                while (entries.hasMoreElements()) {
                    val className = entries.nextElement().replace('/', '.')
                    for (prefix in activePrefixes()) {
                        if (className.startsWith(prefix)) {
                            matched.add(prefix)
                            break
                        }
                    }
                }
            } finally {
                try { dexFile.close() } catch (_: Exception) {}
            }
            DexScanResult(
                packageName = packageName,
                isHostile = matched.isNotEmpty(),
                matchedSdks = matched.toList(),
                error = null,
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun scanViaZip(apkPath: String, packageName: String): DexScanResult {
        val matched = linkedSetOf<String>()
        val dexNamePattern = Regex("""classes\d*\.dex""")

        return try {
            ZipFile(apkPath).use { zip ->
                val dexEntries = zip.entries().asSequence()
                    .filter { dexNamePattern.matches(it.name) }

                for (entry in dexEntries) {
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    // DEX class descriptors are stored as L-prefixed
                    // slash paths, e.g. "Lio/appmetrica/analytics/AppMetrica;"
                    // ISO_8859_1 is a byte-safe decode — each byte maps to
                    // the same code-point, so ASCII substring search works.
                    val content = String(bytes, Charsets.ISO_8859_1)
                    for (prefix in activePrefixes()) {
                        if (prefix in matched) continue
                        val needle = "L${prefix.replace('.', '/')}/"
                        if (content.contains(needle)) {
                            matched.add(prefix)
                        }
                    }
                    if (matched.size == activePrefixes().size) break
                }
            }
            DexScanResult(
                packageName = packageName,
                isHostile = matched.isNotEmpty(),
                matchedSdks = matched.toList(),
                error = null,
            )
        } catch (e: Exception) {
            DexScanResult(packageName, false, emptyList(), e.message)
        }
    }
}
