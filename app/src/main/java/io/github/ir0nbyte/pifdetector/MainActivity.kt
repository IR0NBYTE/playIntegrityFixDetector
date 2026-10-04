package io.github.ir0nbyte.pifdetector

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import io.github.ir0nbyte.pifdetector.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private var binding: ActivityMainBinding? = null
    private val resultAdapter = ResultAdapter()
    private val runner = DetectionRunner()

    /*
     * Held so the report can be exported after a run. A screenshot was the only
     * thing a user could attach to an issue, and it carries the verdicts
     * without any of the evidence behind them.
     */
    private var lastRows: List<DetectionResult>? = null
    private var lastReport: DetectionReport? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (!DetectionRunner.isAvailable) {
            showErrorAndExit(getString(R.string.dialog_native_lib_failed))
            return
        }

        if (!runner.verifyFlagsInSync(DetectionResult.ALL_FLAGS_MASK)) {
            Log.e(TAG, "Bitmask flag SSOT mismatch -- check DetectionResult.kt vs native-lib.cpp")
            if (BuildConfig.DEBUG) {
                Toast.makeText(this,
                    "DEV: bitmask flag SSOT mismatch (see logcat)",
                    Toast.LENGTH_LONG).show()
            }
        }

        val activityBinding = ActivityMainBinding.inflate(layoutInflater)
        binding = activityBinding
        setContentView(activityBinding.root)

        activityBinding.resultsRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = resultAdapter
        }

        setupRevocationToggle()
        setupDetectionButton()
        showPrivacyNoticeIfNeeded()
    }

    private fun setupRevocationToggle() {
        val toggle = binding?.revocationSwitch ?: return
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        toggle.isChecked = prefs.getBoolean(KEY_ONLINE_REFRESH, true)
        toggle.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(KEY_ONLINE_REFRESH, isChecked).apply()
        }
    }

    private fun isOnlineRefreshEnabled(): Boolean =
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).getBoolean(KEY_ONLINE_REFRESH, true)

    /**
     * The offline revocation check always runs. This notice covers only the
     * optional online refresh, which is the sole outbound request the app makes
     * during a check.
     */
    private fun showPrivacyNoticeIfNeeded() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        if (prefs.getBoolean(KEY_PRIVACY_NOTICE_SHOWN, false)) return

        AlertDialog.Builder(this)
            .setTitle(R.string.privacy_revocation_title)
            .setMessage(R.string.privacy_revocation_body)
            .setCancelable(false)
            .setPositiveButton(R.string.privacy_revocation_keep_on) { _, _ ->
                prefs.edit()
                    .putBoolean(KEY_ONLINE_REFRESH, true)
                    .putBoolean(KEY_PRIVACY_NOTICE_SHOWN, true)
                    .apply()
                binding?.revocationSwitch?.isChecked = true
            }
            .setNegativeButton(R.string.privacy_revocation_offline_only) { _, _ ->
                prefs.edit()
                    .putBoolean(KEY_ONLINE_REFRESH, false)
                    .putBoolean(KEY_PRIVACY_NOTICE_SHOWN, true)
                    .apply()
                binding?.revocationSwitch?.isChecked = false
            }
            .show()
    }

    private fun setupDetectionButton() {
        val detectBtn = binding?.button2 ?: return
        detectBtn.setOnClickListener {
            detectBtn.isEnabled = false
            detectBtn.setText(R.string.button_running)
            binding?.statusSubtitle?.setText(R.string.status_running_subtitle)
            runIntegrityCheck(detectBtn)
        }
    }

    private fun runIntegrityCheck(detectBtn: Button) {
        runner.runCheck(this, isOnlineRefreshEnabled()) { report ->

            detectBtn.isEnabled = true
            detectBtn.setText(R.string.button_run)

            val results = DetectionResult.fromBitmask(
                report.bitmask, report.revocation, report.crossSource, report.validity,
                report.versions, report.shape, report.moduleHash, report.reasons,
            )
            // One state per row, so these three buckets cannot overlap and no
            // caller has to re-derive a precedence order. They previously did,
            // and the list and the summary card ordered two of the states
            // differently.
            val detectedCount = results.count { it.state.isFinding }
            val unobservableCount = results.count { !it.state.isObservable }
            val unresolvedCount = results.count { it.state.needsReview }
            val observableTotal = results.size - unobservableCount

            lastRows = results
            lastReport = report
            invalidateOptionsMenu()
            resultAdapter.submitList(results)
            binding?.resultsRecyclerView?.visibility = View.VISIBLE

            updateStatusCard(
                detectedCount, observableTotal, unobservableCount, unresolvedCount
            )
        }
    }

    private fun updateStatusCard(
        detectedCount: Int,
        observableTotal: Int,
        unobservableCount: Int,
        unresolvedCount: Int,
    ) {
        val b = binding ?: return
        when {
            detectedCount > 0 -> renderViolation(b, detectedCount, observableTotal)
            unresolvedCount > 0 -> renderReview(b, unresolvedCount, observableTotal)
            else -> renderClean(b, observableTotal, unobservableCount, unresolvedCount)
        }
    }

    private fun renderClean(
        b: ActivityMainBinding,
        total: Int,
        unobservable: Int,
        unresolved: Int,
    ) {
        b.statusTitle.setText(R.string.status_pass_title)
        b.statusSubtitle.text = if (unobservable > 0 || unresolved > 0) {
            getString(R.string.status_pass_subtitle_partial, total, unobservable, unresolved)
        } else {
            getString(R.string.status_pass_subtitle, total)
        }
        b.statusIcon.setImageResource(R.drawable.ic_check)
        b.statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.status_pass))
        b.statusCard.setCardBackgroundColor(ContextCompat.getColor(this, R.color.card_clean))
    }

    /** Nothing was detected, but something observable did not resolve to a pass. */
    private fun renderReview(b: ActivityMainBinding, unresolved: Int, total: Int) {
        b.statusTitle.setText(R.string.status_review_title)
        b.statusSubtitle.text = getString(R.string.status_review_subtitle, unresolved, total)
        b.statusIcon.setImageResource(R.drawable.ic_info)
        b.statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.status_warn))
        b.statusCard.setCardBackgroundColor(ContextCompat.getColor(this, R.color.card_review))
    }

    private fun renderViolation(b: ActivityMainBinding, detected: Int, total: Int) {
        b.statusTitle.setText(R.string.status_fail_title)
        b.statusSubtitle.text = getString(R.string.status_fail_subtitle, detected, total)
        b.statusIcon.setImageResource(R.drawable.ic_warning)
        b.statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.status_fail))
        b.statusCard.setCardBackgroundColor(ContextCompat.getColor(this, R.color.card_detected))
    }

    private fun showErrorAndExit(message: String) {
        if (isFinishing || isDestroyed) return

        AlertDialog.Builder(this)
            .setTitle(R.string.dialog_error_title)
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton(R.string.dialog_button_exit) { _, _ -> finish() }
            .show()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId != R.id.action_export_report) return super.onOptionsItemSelected(item)
        exportReport()
        return true
    }

    private fun exportReport() {
        val rows = lastRows
        val report = lastReport
        if (rows == null || report == null) {
            Toast.makeText(this, R.string.export_report_unavailable, Toast.LENGTH_SHORT).show()
            return
        }
        val text = ReportBuilder.build(
            rows, report, report.presentation,
            appVersion = "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
        )
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, getString(R.string.export_report_subject))
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(send, getString(R.string.action_export_report)))
    }

    override fun onDestroy() {
        super.onDestroy()
        runner.shutdown()
        lastRows = null
        lastReport = null
        binding = null
    }

    private companion object {
        const val TAG = "MainActivity"
        const val PREFS_NAME = "pifd_settings"

        // Renamed from revocation_check_enabled so existing installs adopt the
        // new default instead of inheriting a stale false.
        const val KEY_ONLINE_REFRESH = "revocation_online_refresh_enabled"
        const val KEY_PRIVACY_NOTICE_SHOWN = "privacy_notice_shown"
    }
}
