package io.github.ir0nbyte.pifdetector

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.scottyab.rootbeer.RootBeer
import io.github.ir0nbyte.pifdetector.databinding.ActivityMainBinding
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private var binding: ActivityMainBinding? = null
    private var rootChecker: RootBeer? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val resultAdapter = ResultAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (!nativeLibLoaded) {
            showErrorAndExit("Native security module failed to load")
            return
        }

        val activityBinding = ActivityMainBinding.inflate(layoutInflater)
        binding = activityBinding
        setContentView(activityBinding.root)

        activityBinding.resultsRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = resultAdapter
        }

        rootChecker = RootBeer(this)

        if (performInitialSecurityCheck()) {
            setupDetectionButton()
        }
    }

    private fun performInitialSecurityCheck(): Boolean {
        if (rootChecker?.isRooted == true) {
            showSecurityAlert(
                "Root Detected",
                "This device has been rooted. The app cannot verify integrity on compromised systems."
            )
            return false
        }
        return true
    }

    private fun setupDetectionButton() {
        val detectBtn = binding?.button2 ?: return

        detectBtn.setOnClickListener {
            detectBtn.isEnabled = false
            detectBtn.text = "Checking..."
            binding?.statusSubtitle?.text = "Running integrity checks..."
            runIntegrityCheck(detectBtn)
        }
    }

    private fun runIntegrityCheck(detectBtn: android.widget.Button) {
        executor.execute {
            val result = isIntegrityTampered()

            mainHandler.post {
                if (isFinishing || isDestroyed) return@post

                detectBtn.isEnabled = true
                detectBtn.text = "Run Integrity Check"

                val results = DetectionResult.fromBitmask(result)
                val detectedCount = results.count { it.detected }

                resultAdapter.submitResults(results)
                binding?.resultsRecyclerView?.visibility = View.VISIBLE

                updateStatusCard(detectedCount, results.size)
            }
        }
    }

    private fun updateStatusCard(detectedCount: Int, totalCount: Int) {
        val b = binding ?: return

        if (detectedCount == 0) {
            b.statusTitle.text = "Integrity Verified"
            b.statusSubtitle.text = "All $totalCount checks passed"
            b.statusIcon.setImageResource(R.drawable.ic_check)
            b.statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.status_pass))
            b.statusCard.setCardBackgroundColor(ContextCompat.getColor(this, R.color.card_clean))
        } else {
            b.statusTitle.text = "Integrity Violation"
            b.statusSubtitle.text = "$detectedCount of $totalCount checks failed"
            b.statusIcon.setImageResource(R.drawable.ic_warning)
            b.statusIcon.setColorFilter(ContextCompat.getColor(this, R.color.status_fail))
            b.statusCard.setCardBackgroundColor(ContextCompat.getColor(this, R.color.card_detected))
        }
    }

    private fun showSecurityAlert(title: String, message: String) {
        if (isFinishing || isDestroyed) return

        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton("Exit") { _, _ -> finish() }
            .show()
    }

    private fun showErrorAndExit(message: String) {
        if (isFinishing || isDestroyed) return

        AlertDialog.Builder(this)
            .setTitle("Error")
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton("Exit") { _, _ -> finish() }
            .show()
    }

    override fun onDestroy() {
        super.onDestroy()
        executor.shutdownNow()
        binding = null
        rootChecker = null
    }

    private external fun isIntegrityTampered(): Int

    companion object {
        private var nativeLibLoaded = false

        init {
            try {
                System.loadLibrary("pifdetector")
                nativeLibLoaded = true
            } catch (_: UnsatisfiedLinkError) {
            }
        }
    }
}
