package io.nekohasekai.sagernet.scanner

/**
 * Layer 1 — package name prefix matcher.
 *
 * Cheapest check (<1 ms per package). Catches first-party Russian apps
 * that brand themselves under known prefixes. Misses third-party apps
 * that embed Russian SDKs without adopting the naming convention —
 * Layer 4 (DEX class scan) handles those.
 *
 * Matching is prefix-based (startsWith) so e.g. "ru.yandex." catches
 * `ru.yandex.searchplugin`, `ru.yandex.taxi`, `ru.yandex.market`, etc.
 */
object HostilePackagePatterns {
    val PREFIXES: List<String> = listOf(
        // Yandex ecosystem
        "ru.yandex.",
        "com.yandex.",

        // Russian banking (legally required to detect VPN in Russia)
        "ru.sberbank",
        "com.idamob.tinkoff",        // Tinkoff (T-Bank)
        "ru.alfabank",
        "ru.vtb24",
        "ru.raiffeisennews",
        "ru.rosbank",

        // Russian telcos
        "ru.mts.",
        "ru.beeline.",
        "ru.megafon.",
        "ru.tele2.",
        "ru.rt.",                    // Rostelecom

        // VK / Mail.ru ecosystem (state-affiliated since 2023)
        "com.vkontakte.",
        "ru.ok.",
        "ru.mail.",
        "com.vk.",
        "com.max.messenger",         // MAX — state-mandated messenger

        // Russian marketplaces (April 15 2026 directive targets)
        "ru.ozon.",
        "ru.wildberries.",

        // Russian government services
        "ru.gosuslugi",
        "ru.mos.",                   // Mos.ru
        "ru.nalog.",                 // Federal Tax Service
        "ru.rzd.",                   // Russian Railways

        // Russian security / antivirus (active VPN detectors)
        "com.kaspersky.",
        "com.drweb.",
    )

    fun matches(packageName: String): Boolean =
        PREFIXES.any { packageName.startsWith(it) }
}
