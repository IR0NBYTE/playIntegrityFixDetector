package io.github.ir0nbyte.pifdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The reason pipe, exercised through the real path rather than through the UI.
 *
 * The engine returns one array holding the bitmask and the reason codes. A unit
 * test cannot reach it, and driving the screen means fighting whatever else is
 * in the foreground on a lab device, so this runs the actual detection and
 * inspects the report it produces.
 */
@RunWith(AndroidJUnit4::class)
class ReasonPipeInstrumentedTest {

    private fun runEngine(): DetectionReport {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val runner = DetectionRunner()
        val latch = CountDownLatch(1)
        var captured: DetectionReport? = null

        runner.runCheck(context, onlineRefreshEnabled = false) { report ->
            captured = report
            latch.countDown()
        }
        assertTrue(
            "the engine did not report within 90s",
            latch.await(90, TimeUnit.SECONDS)
        )
        return requireNotNull(captured)
    }

    /**
     * Every code the engine emitted must be one this build can explain,
     * otherwise a report names a check that fired and cannot say why.
     */
    @Test
    fun everyReasonTheEngineReturnedIsExplainable() {
        val report = runEngine()
        val unknown = report.reasons.filterNot { it in ReasonCodes.knownCodes }
        assertEquals(
            "the engine emitted reason codes this build has no text for: $unknown",
            emptyList<Int>(),
            unknown
        )
    }

    /** A reason must never arrive for a bit the engine did not set. */
    @Test
    fun reasonsOnlyExplainBitsThatAreActuallySet() {
        val report = runEngine()
        val rows = DetectionResult.fromBitmask(
            report.bitmask, report.revocation, report.crossSource, report.validity,
            report.versions, report.shape, report.moduleHash, report.reasons,
        )
        for (row in rows) {
            if (row.reasons.isNotEmpty()) {
                assertTrue(
                    "${row.name} carries reasons but its bit is not set",
                    report.bitmask and row.flag != 0
                )
            }
        }
    }

    /**
     * The emulators and lab handsets this runs on are userdebug, so the
     * bootloader row fires. It is the one row wired for reasons on every arm,
     * which makes it the check that proves the pipe carries anything at all.
     */
    @Test
    fun aSetBootloaderBitArrivesWithAReasonNamingTheProperty() {
        val report = runEngine()
        val bootloaderSet = report.bitmask and DetectionResult.DETECTION_BOOTLOADER != 0
        if (!bootloaderSet) return  // a genuinely locked device has nothing to explain

        val rows = DetectionResult.fromBitmask(
            report.bitmask, report.revocation, report.crossSource, report.validity,
            report.versions, report.shape, report.moduleHash, report.reasons,
        )
        val row = rows.first { it.flag == DetectionResult.DETECTION_BOOTLOADER }
        assertTrue(
            "the bootloader bit is set but nothing says which property did it",
            row.reasons.isNotEmpty()
        )
    }

    /** Running twice must not accumulate reasons from the earlier pass. */
    @Test
    fun reasonsDoNotLeakBetweenRuns() {
        val first = runEngine()
        val second = runEngine()
        assertEquals(
            "a second run returned a different reason count, so the sink is not being cleared",
            first.reasons.sorted(),
            second.reasons.sorted()
        )
    }
}
