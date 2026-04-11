package io.nekohasekai.sagernet.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Scan pipeline orchestrator.
 *
 * - [quickScan] runs Layers 1/2/3/5 synchronously at VPN start.
 *   Target latency: <500 ms for ~100 installed apps.
 * - [scanAll] additionally runs Layer 4 (DEX scan) on Dispatchers.IO.
 *   Reactive only — triggered by first launch and PACKAGE_ADDED /
 *   PACKAGE_REPLACED broadcasts, plus a weekly WorkManager rescan
 *   with charging+idle constraints (Task #19).
 *
 * Never polls, never runs a periodic background service.
 */
class HostileAppScanner(private val context: Context) {

    /**
     * Full pipeline, all 5 layers. Includes Layer 4 (DEX scan).
     * Expected runtime: 5-15 s for ~100 apps. Always on IO dispatcher.
     */
    suspend fun scanAll(): List<ScanResult> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val installed = pm.getInstalledApplications(0)
        installed
            .asSequence()
            .filter { !isUntouchableSystemApp(it) }
            .filter { it.packageName != context.packageName }
            .map { scanAppFull(pm, it) }
            .sortedByDescending { it.riskLevel.ordinal }
            .toList()
    }

    /**
     * Quick pipeline — Layers 1/2/3/5 only (skips DEX scan).
     * Expected runtime: <500 ms for ~100 apps. Safe to run
     * synchronously on VPN start.
     */
    suspend fun quickScan(): List<ScanResult> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val installed = pm.getInstalledApplications(0)
        installed
            .asSequence()
            .filter { !isUntouchableSystemApp(it) }
            .filter { it.packageName != context.packageName }
            .map { scanAppQuick(pm, it) }
            .filter { it.riskLevel != RiskLevel.CLEAN }
            .sortedByDescending { it.riskLevel.ordinal }
            .toList()
    }

    private fun scanAppFull(pm: PackageManager, appInfo: ApplicationInfo): ScanResult {
        val pkg = appInfo.packageName
        val name = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(pkg)
        val reasons = mutableListOf<String>()

        val nameMatch = HostilePackagePatterns.matches(pkg)
        if (nameMatch) reasons.add("Russian package name prefix")

        val certMatch = HostileCertificates.check(pm, pkg)
        if (certMatch) reasons.add("Signed by known Russian publisher")

        val manifestMatch = HostileManifestMarkers.check(pm, pkg)
        if (manifestMatch) reasons.add("Russian SDK metadata in manifest")

        val providerMatch = HostileManifestMarkers.checkProviders(pm, pkg)
        if (providerMatch) reasons.add("Russian SDK content provider registered")

        val dexResult = HostileDexScanner.scan(context, pkg)
        if (dexResult.isHostile) {
            reasons.add("Embeds: ${dexResult.matchedSdks.joinToString()}")
        }

        val permMatch = HostilePermissionCheck.check(pm, pkg)
        if (permMatch) reasons.add("Requests QUERY_ALL_PACKAGES")

        val risk = classifyRisk(
            dexHostile = dexResult.isHostile,
            nameMatch = nameMatch,
            certMatch = certMatch,
            manifestMatch = manifestMatch || providerMatch,
            permMatch = permMatch,
        )

        return ScanResult(pkg, name, risk, reasons, dexResult)
    }

    private fun scanAppQuick(pm: PackageManager, appInfo: ApplicationInfo): ScanResult {
        val pkg = appInfo.packageName
        val name = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(pkg)
        val reasons = mutableListOf<String>()

        val nameMatch = HostilePackagePatterns.matches(pkg)
        if (nameMatch) reasons.add("Russian package name prefix")

        val certMatch = HostileCertificates.check(pm, pkg)
        if (certMatch) reasons.add("Signed by known Russian publisher")

        val manifestMatch = HostileManifestMarkers.check(pm, pkg)
        if (manifestMatch) reasons.add("Russian SDK metadata in manifest")

        val providerMatch = HostileManifestMarkers.checkProviders(pm, pkg)
        if (providerMatch) reasons.add("Russian SDK content provider registered")

        val permMatch = HostilePermissionCheck.check(pm, pkg)
        if (permMatch) reasons.add("Requests QUERY_ALL_PACKAGES")

        val risk = classifyRisk(
            dexHostile = false,
            nameMatch = nameMatch,
            certMatch = certMatch,
            manifestMatch = manifestMatch || providerMatch,
            permMatch = permMatch,
        )

        return ScanResult(pkg, name, risk, reasons, null)
    }

    private fun classifyRisk(
        dexHostile: Boolean,
        nameMatch: Boolean,
        certMatch: Boolean,
        manifestMatch: Boolean,
        permMatch: Boolean,
    ): RiskLevel = when {
        dexHostile && (nameMatch || certMatch) -> RiskLevel.CRITICAL
        dexHostile -> RiskLevel.HIGH
        manifestMatch -> RiskLevel.HIGH
        nameMatch || certMatch -> RiskLevel.MEDIUM
        permMatch -> RiskLevel.LOW
        else -> RiskLevel.CLEAN
    }

    /**
     * Skip non-updatable system apps — they can't have embedded
     * Russian SDKs installed post-hoc, and excluding them from the
     * VPN would break system behavior.
     */
    private fun isUntouchableSystemApp(info: ApplicationInfo): Boolean {
        val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val isUpdatedSystem = (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return isSystem && !isUpdatedSystem
    }

    /**
     * Generate sing-box `exclude_package` list from scan results.
     * Anything MEDIUM or higher gets excluded from the VPN tunnel.
     */
    fun toExcludeList(results: List<ScanResult>): List<String> =
        results
            .filter { it.riskLevel.ordinal >= RiskLevel.MEDIUM.ordinal }
            .map { it.packageName }
}
