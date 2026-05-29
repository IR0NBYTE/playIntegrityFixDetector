package io.github.ir0nbyte.pifdetector

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/*
 * Owns the worker executor and the JNI call. Activity stays UI-only.
 *
 * The JNI binding is on this class -- not on Activity -- so the native
 * lib's RegisterNatives target is stable across Activity recreation
 * (rotation, theme change). System.loadLibrary side-effects happen once
 * per process via the companion object.
 *
 * Cancellation: the native call cannot be interrupted from JNI, so a
 * shutdown() doesn't actually stop it -- it just sets a cancelled flag
 * and the result post is suppressed. Callers no longer need to check
 * activity lifecycle inside the result lambda.
 */
class DetectionRunner {

    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val cancelled = AtomicBoolean(false)
    private val attestationProbe = KeyAttestationProbe()

    /*
     * @param revocationEnabled user setting (default false): when true, the
     * attestation probe may make ONE bounded network call to Google's
     * revocation list for a genuinely Google-anchored chain. When false the
     * probe stays fully offline. The flag is read on the UI thread (from
     * SharedPreferences) and passed in so this class needs no Context.
     */
    fun runCheck(revocationEnabled: Boolean, onResult: (Int) -> Unit) {
        executor.execute {
            // Native engine first; the key-attestation probe (Kotlin, since it
            // drives the AndroidKeyStore API) then ORs in DETECTION_ATTEST_ANOMALY.
            // It takes the native bitmask so its contradiction check can reuse
            // the bootloader/root signals the engine already computed.
            val nativeMask = isIntegrityTampered()
            val bitmask = nativeMask or attestationProbe.probe(nativeMask, revocationEnabled)
            mainHandler.post {
                if (!cancelled.get()) onResult(bitmask)
            }
        }
    }

    fun shutdown() {
        cancelled.set(true)
        executor.shutdownNow()
    }

    private external fun isIntegrityTampered(): Int

    private external fun nativeAllFlagsMask(): Int

    /*
     * SSOT verification: returns true if Kotlin's flag constants OR'd
     * together equal the native side's all-flags mask. Used at startup
     * to fail loudly if someone adds a flag in only one place.
     */
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

        private var nativeLibLoaded = false
        val isAvailable: Boolean get() = nativeLibLoaded

        init {
            try {
                System.loadLibrary("pifdetector")
                nativeLibLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load libpifdetector.so", e)
            }
        }
    }
}
