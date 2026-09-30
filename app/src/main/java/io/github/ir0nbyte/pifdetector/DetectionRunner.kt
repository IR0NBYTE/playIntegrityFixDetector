package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

data class DetectionReport(val bitmask: Int, val revocation: RevocationStatus)

class DetectionRunner {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val cancelled = AtomicBoolean(false)
    private val attestationProbe = KeyAttestationProbe()
    private val activeAttestationProbe = ActiveAttestationProbe()

    fun runCheck(
        context: Context,
        onlineRefreshEnabled: Boolean,
        onResult: (DetectionReport) -> Unit,
    ) {
        val appContext = context.applicationContext
        executor.execute {
            val nativeMask = isIntegrityTampered(appContext)
            val passive = attestationProbe.probe(nativeMask, onlineRefreshEnabled, appContext)

            val activeMask = activeAttestationProbe.probe(passive.mask != 0)
            val report = DetectionReport(
                bitmask = nativeMask or passive.mask or activeMask,
                revocation = passive.revocation,
            )
            mainHandler.post {
                if (!cancelled.get()) onResult(report)
            }
        }
    }

    fun shutdown() {
        cancelled.set(true)
        executor.shutdownNow()
    }

    private external fun isIntegrityTampered(context: Context): Int

    private external fun nativeAllFlagsMask(): Int

    private external fun nativeSelfTest(): Int

    fun malformedPropertyLiterals(): Int = try {
        nativeSelfTest()
    } catch (e: UnsatisfiedLinkError) {
        Log.e(TAG, "nativeSelfTest not bound", e)
        -1
    }

    fun verifyFlagsInSync(kotlinMask: Int): Boolean {
        return try {
            nativeAllFlagsMask() == kotlinMask
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "nativeAllFlagsMask not bound", e)
            false
        }
    }

    companion object {
        private const val TAG = "DetectionRunner"

        val isAvailable: Boolean = try {
            System.loadLibrary("pifdetector")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libpifdetector.so", e)
            false
        }
    }
}
