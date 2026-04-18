package io.nekohasekai.sagernet.scanner

import android.content.pm.PackageManager

/**
 * Layer 3 — manifest metadata + content provider scan.
 *
 * Russian SDKs declare meta-data keys in AndroidManifest.xml for
 * initialization and register content providers with well-known
 * authorities. Catches apps that embed the SDK but don't initialize it
 * via code-only paths (Layer 4 catches those).
 *
 * Cost: ~2 ms per package (one PackageManager lookup per check).
 */
object HostileManifestMarkers {

    /**
     * meta-data keys declared by Russian SDKs in their AndroidManifest.xml
     * during auto-init. Matching any one of these in the target app's
     * meta-data bundle indicates the SDK is embedded.
     */
    val BUILTIN_METADATA_KEYS: List<String> = listOf(
        // Yandex AppMetrica (both modern and legacy key formats)
        "io.appmetrica.analytics.API_KEY",
        "com.yandex.android.appmetrica.api_key",
        "yandex_mobile_metrica_api_key",

        // MyTracker (Mail.ru Group, forced to RU servers since 2023)
        "com.my.tracker.appId",
        "com.my.target.myTrackerSdkKey",

        // VK SDK (auth, social, ads)
        "com.vk.sdk.AppId",
        "VKSdkAppId",

        // Yandex Ads
        "com.yandex.mobile.ads.BLOCK_ID",

        // Top.Mail.ru counter
        "mail.ru.top.counter.id",
    )

    /**
     * Content provider authorities registered by Russian SDKs. If a
     * target app registers any provider whose authority contains one
     * of these substrings, it's almost certainly running the SDK.
     */
    val BUILTIN_PROVIDER_AUTHORITIES: List<String> = listOf(
        "io.appmetrica.analytics",
        "com.yandex.metrica",
        "com.my.tracker",
        "com.my.target",
        "com.vk.api",
    )

    fun check(pm: PackageManager, packageName: String): Boolean {
        return try {
            val appInfo = pm.getApplicationInfo(
                packageName,
                PackageManager.GET_META_DATA,
            )
            val metadata = appInfo.metaData ?: return false
            val remote = SignatureRegistry.current().metadataKeys
            (BUILTIN_METADATA_KEYS + remote).any { key -> metadata.containsKey(key) }
        } catch (_: PackageManager.NameNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }

    fun checkProviders(pm: PackageManager, packageName: String): Boolean {
        return try {
            val info = pm.getPackageInfo(
                packageName,
                PackageManager.GET_PROVIDERS,
            )
            val providers = info.providers ?: return false
            val remote = SignatureRegistry.current().providerAuthorities
            val combined = BUILTIN_PROVIDER_AUTHORITIES + remote
            providers.any { provider ->
                val authority = provider.authority ?: return@any false
                combined.any { needle -> authority.contains(needle) }
            }
        } catch (_: PackageManager.NameNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }
}
