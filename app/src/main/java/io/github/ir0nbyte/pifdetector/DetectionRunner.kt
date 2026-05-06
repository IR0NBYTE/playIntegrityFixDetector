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

    fun runCheck(onResult: (Int) -> Unit) {
        executor.execute {
            val bitmask = isIntegrityTampered()
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
