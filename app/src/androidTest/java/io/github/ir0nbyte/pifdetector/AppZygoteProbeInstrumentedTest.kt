package io.github.ir0nbyte.pifdetector

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs the real app zygote probe and logs what it saw. It asserts nothing
 * about the device: an unobservable child is a legitimate outcome and passes.
 */
@RunWith(AndroidJUnit4::class)
class AppZygoteProbeInstrumentedTest {

    @Test
    fun logWhatTheIsolatedChildSees() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val outcome = AppZygoteProbe().observe(ctx)
        val line = when (outcome) {
            is AppZygoteProbe.Outcome.Observed ->
                "PIFD_APPZYGOTE outcome=Observed child=${outcome.childReasons}"
            is AppZygoteProbe.Outcome.NotObservable ->
                "PIFD_APPZYGOTE outcome=NotObservable:${outcome.why} child=[]"
        }
        Log.i(TAG, line)
        println(line)
        if (outcome is AppZygoteProbe.Outcome.Observed) {
            assertTrue(
                "the child reports only the three mount reasons: ${outcome.childReasons}",
                outcome.childReasons.all { it in AppZygoteCheck.COMPARED_REASONS }
            )
        }
    }

    @Test
    fun refusesOnTheMainThread() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        var outcome: AppZygoteProbe.Outcome? = null
        instrumentation.runOnMainSync {
            outcome = AppZygoteProbe().observe(instrumentation.targetContext)
        }
        val why = (outcome as? AppZygoteProbe.Outcome.NotObservable)?.why
        if (android.os.Build.VERSION.SDK_INT >= 29) {
            assertEquals("main thread", why)
        } else {
            assertTrue("below API 29 it never binds: $why", why?.startsWith("api") == true)
        }
    }

    private companion object {
        const val TAG = "PIFD_APPZYGOTE"
    }
}
