package io.nekohasekai.sagernet.scanner

data class DexScanResult(
    val packageName: String,
    val isHostile: Boolean,
    val matchedSdks: List<String>,
    val error: String?,
) {
    fun describe(): String {
        if (!isHostile) return "$packageName: clean"
        return "$packageName: HOSTILE (${matchedSdks.joinToString(", ") { sdkName(it) }})"
    }

    private fun sdkName(prefix: String): String = when {
        prefix.contains("appmetrica") -> "Yandex AppMetrica"
        prefix.contains("yandex.metrica") -> "Yandex Metrica (legacy)"
        prefix.contains("my.tracker") -> "MyTracker (Mail.ru)"
        prefix.contains("my.target") -> "myTarget (VK Ads)"
        prefix.contains("yandex.mobile.ads") -> "Yandex Ads"
        prefix.contains("yandex.mapkit") -> "Yandex MapKit"
        prefix.contains("vk.") -> "VK SDK"
        prefix.contains("ok.android") -> "OK.ru SDK"
        prefix.contains("kaspersky") -> "Kaspersky SDK"
        prefix.contains("sberbank") || prefix.contains("sber.") -> "Sber SDK"
        prefix.contains("tinkoff") -> "Tinkoff SDK"
        prefix.contains("nspk.mirpay") -> "Mir Pay"
        prefix.contains("rtlabs") -> "Gosuslugi Auth"
        prefix.contains("mail.") -> "Mail.ru SDK"
        else -> prefix
    }
}
