package io.github.ir0nbyte.pifdetector

import android.content.Context
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
    private val activeAttestationProbe = ActiveAttestationProbe()

    /*
     * @param revocationEnabled user setting (default false): when true, the
     * attestation probe may make ONE bounded network call to Google's
     * revocation list for a genuinely Google-anchored chain. When false the
     * probe stays fully offline. The flag is read on the UI thread (from
     * SharedPreferences) and passed in so this class needs no Context.
     */
    fun runCheck(context: Context, revocationEnabled: Boolean, onResult: (Int) -> Unit) {
        // applicationContext, not the caller's: the worker outlives the Activity
        // and the native side only needs PackageManager / ApplicationInfo.
        val appContext = context.applicationContext
        executor.execute {
            // Native engine first; the two Kotlin attestation probes (which drive
            // the AndroidKeyStore API) then OR in their bits. The passive probe
            // takes the native bitmask so its contradiction check can reuse the
            // bootloader/root signals the engine already computed; the active one
            // provokes its own evidence and needs no context.
            val nativeMask = isIntegrityTampered(appContext)
            val passiveMask = attestationProbe.probe(nativeMask, revocationEnabled)
            // The active probe is told whether the passive one already flagged so
            // it does not re-report a device that simply has no hardware
            // attestation as a second, separate forgery finding.
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

        // Computed once at class init; immutable so there is no cross-thread
        // visibility concern around the load result.
        val isAvailable: Boolean = try {
            System.loadLibrary("pifdetector")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load libpifdetector.so", e)
            false
        }
    }
}
