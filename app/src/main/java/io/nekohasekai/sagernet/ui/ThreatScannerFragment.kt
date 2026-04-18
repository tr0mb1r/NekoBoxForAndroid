package io.nekohasekai.sagernet.ui

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.ktx.snackbar
import io.nekohasekai.sagernet.scanner.HostileAppScanner
import io.nekohasekai.sagernet.scanner.HostileScanPrefs
import io.nekohasekai.sagernet.scanner.RiskLevel
import io.nekohasekai.sagernet.scanner.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Review UI for hostile-app scanner results.
 *
 * Runs `HostileAppScanner.quickScan()` on open (Layers 1/2/3/5 — no
 * DEX, under 500 ms for ~100 apps), groups results by risk level,
 * shows a checkbox per app preselected to "exclude from VPN" for
 * anything MEDIUM or higher. User can uncheck individual entries
 * and tap Apply to persist opt-outs; opt-outs take effect on the
 * next VPN reconnect.
 */
class ThreatScannerFragment : ToolbarFragment(R.layout.layout_threat_scanner) {

    private lateinit var list: LinearLayout
    private lateinit var status: TextView
    private lateinit var rescan: MaterialButton
    private lateinit var apply: MaterialButton

    private val pendingOptOut = mutableSetOf<String>()
    private var currentResults: List<ScanResult> = emptyList()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        toolbar.title = "Threat Scanner"

        list = view.findViewById(R.id.threat_scanner_list)
        status = view.findViewById(R.id.threat_scanner_status)
        rescan = view.findViewById(R.id.threat_scanner_rescan)
        apply = view.findViewById(R.id.threat_scanner_apply)

        rescan.setOnClickListener { runScan() }
        apply.setOnClickListener { applyOptOuts() }

        runScan()
    }

    private fun runScan() {
        val ctx = requireContext()
        status.text = "Scanning..."
        list.removeAllViews()
        pendingOptOut.clear()
        pendingOptOut.addAll(HostileScanPrefs.userOptOut(ctx))

        lifecycleScope.launch {
            val results = withContext(Dispatchers.IO) {
                HostileAppScanner(ctx).quickScan()
            }
            currentResults = results
            renderResults(results)
        }
    }

    private fun renderResults(results: List<ScanResult>) {
        list.removeAllViews()

        if (results.isEmpty()) {
            status.text = "No flagged apps. Everything scanned clean."
            return
        }

        val byRisk = results.groupBy { it.riskLevel }
        val order = listOf(RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW)

        renderStatusOnly()

        for (risk in order) {
            val group = byRisk[risk] ?: continue
            list.addView(buildHeader(risk, group.size))
            for (result in group.sortedBy { it.appName.lowercase() }) {
                list.addView(buildRow(result))
            }
        }
    }

    private fun buildHeader(risk: RiskLevel, count: Int): View {
        val ctx = requireContext()
        val (label, color) = when (risk) {
            RiskLevel.CRITICAL -> "CRITICAL — exclude from VPN" to Color.parseColor("#D32F2F")
            RiskLevel.HIGH -> "HIGH — recommend exclude" to Color.parseColor("#F57C00")
            RiskLevel.MEDIUM -> "MEDIUM — flagged" to Color.parseColor("#FBC02D")
            RiskLevel.LOW -> "LOW — privilege heuristic only" to Color.parseColor("#9E9E9E")
            RiskLevel.CLEAN -> "CLEAN" to Color.parseColor("#388E3C")
        }
        return TextView(ctx).apply {
            text = "$label  ($count)"
            setTextColor(color)
            textSize = 14f
            setPadding(0, 24, 0, 8)
            setTypeface(typeface, Typeface.BOLD)
        }
    }

    private fun buildRow(result: ScanResult): View {
        val ctx = requireContext()
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = 4; bottomMargin = 4 }
            gravity = Gravity.CENTER_VERTICAL
        }

        val cb = CheckBox(ctx).apply {
            isChecked = result.riskLevel.ordinal >= RiskLevel.MEDIUM.ordinal &&
                result.packageName !in pendingOptOut
            isEnabled = result.riskLevel.ordinal >= RiskLevel.MEDIUM.ordinal
            setOnCheckedChangeListener { _, checked ->
                if (checked) pendingOptOut.remove(result.packageName)
                else pendingOptOut.add(result.packageName)
                renderStatusOnly()
            }
        }

        val text = TextView(ctx).apply {
            val reasonSummary = result.reasons.joinToString(" • ").ifEmpty { "no specific signals" }
            text = "${result.appName}\n${result.packageName}\n$reasonSummary"
            textSize = 12f
            setPadding(8, 0, 0, 0)
        }

        row.addView(cb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ))
        row.addView(text, LinearLayout.LayoutParams(
            0,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            1f,
        ))
        return row
    }

    private fun renderStatusOnly() {
        val total = currentResults.size
        val excluded = currentResults.count {
            it.riskLevel.ordinal >= RiskLevel.MEDIUM.ordinal && it.packageName !in pendingOptOut
        }
        status.text = "$excluded of $total flagged apps will be excluded from the VPN."
    }

    private fun applyOptOuts() {
        HostileScanPrefs.setUserOptOut(requireContext(), pendingOptOut.toSet())
        snackbar("Saved. Reconnect VPN to apply.").show()
    }
}
