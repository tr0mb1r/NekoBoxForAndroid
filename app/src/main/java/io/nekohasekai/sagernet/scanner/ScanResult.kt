package io.nekohasekai.sagernet.scanner

data class ScanResult(
    val packageName: String,
    val appName: String,
    val riskLevel: RiskLevel,
    val reasons: List<String>,
    val dexResult: DexScanResult?,
)
