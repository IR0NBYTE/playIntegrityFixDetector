package io.github.ir0nbyte.pifdetector

import android.os.Bundle
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Prints the full verdict of one real run, so a bench device can be read
 * without attaching a debugger.
 *
 * The bitmask and the reason codes, including the attestation bits only the
 * Kotlin probes set, are emitted as a single line, both to logcat under the tag
 * pifd and through the instrumentation status stream, where `am instrument -w`
 * shows it. Nothing else about the device is printed. The test asserts only
 * that the engine answered, never what it answered.
 */
@RunWith(AndroidJUnit4::class)
class VerdictDumpInstrumentedTest {

    @Test
    fun dumpVerdict() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val latch = CountDownLatch(1)
        var captured: DetectionReport? = null

        DetectionRunner().runCheck(instrumentation.targetContext, onlineRefreshEnabled = false) { report ->
            captured = report
            latch.countDown()
        }
        assertTrue(
            "the engine did not report within 90s",
            latch.await(90, TimeUnit.SECONDS)
        )
        val report = requireNotNull(captured)

        val line = "PIFD_VERDICT mask=0x${Integer.toHexString(report.bitmask)} " +
            "reasons=${report.reasons.sorted()}"
        Log.i("pifd", line)
        instrumentation.sendStatus(
            STATUS_CODE,
            Bundle().apply {
                putString("pifd_verdict", line)
                putString("stream", line + "\n")
            }
        )
    }

    private companion object {
        /** Outside the codes AndroidJUnitRunner reserves for test lifecycle events. */
        const val STATUS_CODE = 2
    }
}
