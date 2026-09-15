package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class DetectionRunner {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val cancelled = AtomicBoolean(false)
    private val attestationProbe = KeyAttestationProbe()
    private val activeAttestationProbe = ActiveAttestationProbe()

    fun runCheck(context: Context, revocationEnabled: Boolean, onResult: (Int) -> Unit) {
        val appContext = context.applicationContext
        executor.execute {
            val nativeMask = isIntegrityTampered(appContext)
            val passiveMask = attestationProbe.probe(nativeMask, revocationEnabled)

            val activeMask = activeAttestationProbe.probe(passiveMask != 0)
            val bitmask = nativeMask or passiveMask or activeMask
            mainHandler.post {
                if (!cancelled.get()) onResult(bitmask)
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
