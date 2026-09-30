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
            val facts = deviceFacts()
            val passive = attestationProbe.probe(nativeMask, onlineRefreshEnabled, appContext, facts)

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

    private external fun nativeDeviceFacts(): Array<String>

    /** Falls back to EMPTY on any failure, so a missing fact never flags. */
    fun deviceFacts(): AttestationAnalysis.DeviceFacts {
        return try {
            val raw = nativeDeviceFacts()
            if (raw.size < DEVICE_FACT_COUNT) return AttestationAnalysis.DeviceFacts.EMPTY
            AttestationAnalysis.DeviceFacts(
                systemSecurityPatch = raw[0].ifBlank { null },
                vendorSecurityPatch = raw[1].ifBlank { null },
                vbmetaDigestHex = raw[2].ifBlank { null },
                vbmetaHashAlg = raw[3].ifBlank { null },
            )
        } catch (e: Throwable) {
            Log.w(TAG, "device facts unavailable", e)
            AttestationAnalysis.DeviceFacts.EMPTY
        }
    }

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
        private const val DEVICE_FACT_COUNT = 4

        val isAvailable: Boolean = try {
            System.loadLibrary("pifdetector")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libpifdetector.so", e)
            false
        }
    }
}
