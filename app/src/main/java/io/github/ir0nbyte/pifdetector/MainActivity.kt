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
            // SSOT drift: native and Kotlin disagree on the flag set.
            // Always log; surface as a toast in debug builds so it can't
            // be silently shipped.
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

        setupDetectionButton()
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
        runner.runCheck { bitmask ->
            // DetectionRunner.shutdown() suppresses callbacks after destroy,
            // so we don't need an isFinishing/isDestroyed guard here.
            detectBtn.isEnabled = true
            detectBtn.setText(R.string.button_run)

            val results = DetectionResult.fromBitmask(bitmask)
            val detectedCount = results.count { it.detected }
            resultAdapter.submitList(results)
            binding?.resultsRecyclerView?.visibility = View.VISIBLE

            updateStatusCard(detectedCount, results.size)
        }
    }

    private fun updateStatusCard(detectedCount: Int, totalCount: Int) {
        val b = binding ?: return
        if (detectedCount == 0) renderClean(b, totalCount)
        else renderViolation(b, detectedCount, totalCount)
    }

    private fun renderClean(b: ActivityMainBinding, total: Int) {
        b.statusTitle.setText(R.string.status_pass_title)
        b.statusSubtitle.text = getString(R.string.status_pass_subtitle, total)
        b.statusIcon.setImageResource(R.drawable.ic_check)
        b.statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.status_pass))
        b.statusCard.setCardBackgroundColor(ContextCompat.getColor(this, R.color.card_clean))
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
    }
}
