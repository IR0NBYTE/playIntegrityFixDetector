package io.github.ir0nbyte.pifdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Invariants of the code integrity check, asserted against a real run.
 *
 * The arms themselves are exercised by the native self test, which synthesises
 * trampolines and maps an anonymous executable page so the machinery is proven
 * to fire on every device the suite touches. What is left to check here is how
 * the result is allowed to be shaped.
 */
@RunWith(AndroidJUnit4::class)
class CodeIntegrityProbeTest {

    private fun run(): DetectionReport {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val runner = DetectionRunner()
        val latch = CountDownLatch(1)
        var captured: DetectionReport? = null
        runner.runCheck(context, onlineRefreshEnabled = false) { captured = it; latch.countDown() }
        assertTrue("engine did not report within 90s", latch.await(90, TimeUnit.SECONDS))
        return requireNotNull(captured)
    }

    private val findingCodes = setOf(1001, 1002, 1003)
    private val corroborationCode = 1004

    /** The bit must never be set without naming the arm that set it. */
    @Test
    fun theBitIsNeverSetWithoutAFindingReason() {
        val report = run()
        val set = report.bitmask and DetectionResult.DETECTION_CODE_INTEGRITY != 0
        if (!set) return
        assertTrue(
            "code integrity fired with no reason explaining which arm did it",
            report.reasons.any { it in findingCodes }
        )
    }

    /**
     * Text divergence corroborates a hook and cannot convict on its own: a
     * hider that can patch a prologue can also redirect a read of the file.
     */
    @Test
    fun textDivergenceNeverAppearsAlone() {
        val report = run()
        if (corroborationCode !in report.reasons) return
        assertTrue(
            "a text divergence was reported without a hook to corroborate",
            report.reasons.any { it in findingCodes }
        )
    }

    /** No finding reason may arrive while the bit is clear. */
    @Test
    fun noCodeIntegrityReasonWithoutTheBit() {
        val report = run()
        val set = report.bitmask and DetectionResult.DETECTION_CODE_INTEGRITY != 0
        if (set) return
        assertFalse(
            "a code integrity reason arrived but the bit is clear",
            report.reasons.any { it in findingCodes }
        )
    }

    /** The row exists and is observable: it needs no privilege to run. */
    @Test
    fun theRowIsNotMarkedPrivilegedOnly() {
        val rows = DetectionResult.fromBitmask(0)
        val row = rows.first { it.flag == DetectionResult.DETECTION_CODE_INTEGRITY }
        assertFalse("this check reads only our own address space", row.privilegedOnly)
    }
}
