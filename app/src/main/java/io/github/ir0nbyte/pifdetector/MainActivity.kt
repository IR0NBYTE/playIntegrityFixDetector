package io.github.ir0nbyte.pifdetector

import android.os.Bundle
import android.util.Log
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

            val results = DetectionResult.fromBitmask(report.bitmask, report.revocation)
            val detectedCount = results.count { it.detected }

            // Three distinct buckets. A privileged-only row is not observable at
            // all; an inconclusive or warning row is observable but did not
            // resolve to a pass. Collapsing them misreports both.
            val privilegedCount = results.count { it.privilegedOnly && !it.detected }
            val unresolvedCount =
                results.count { (it.inconclusive || it.warning) && !it.detected }
            val observableTotal = results.size - privilegedCount

            resultAdapter.submitList(results)
            binding?.resultsRecyclerView?.visibility = View.VISIBLE

            updateStatusCard(detectedCount, observableTotal, privilegedCount, unresolvedCount)
        }
    }

    private fun updateStatusCard(
        detectedCount: Int,
        observableTotal: Int,
        privilegedCount: Int,
        unresolvedCount: Int,
    ) {
        val b = binding ?: return
        when {
            detectedCount > 0 -> renderViolation(b, detectedCount, observableTotal)
            unresolvedCount > 0 -> renderReview(b, unresolvedCount, observableTotal)
            else -> renderClean(b, observableTotal, privilegedCount, unresolvedCount)
        }
    }

    private fun renderClean(
        b: ActivityMainBinding,
        total: Int,
        privileged: Int,
        unresolved: Int,
    ) {
        b.statusTitle.setText(R.string.status_pass_title)
        b.statusSubtitle.text = if (privileged > 0 || unresolved > 0) {
            getString(R.string.status_pass_subtitle_partial, total, privileged, unresolved)
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

    override fun onDestroy() {
        super.onDestroy()
        runner.shutdown()
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
