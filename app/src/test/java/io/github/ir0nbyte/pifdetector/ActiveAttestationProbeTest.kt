package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The provocations themselves need a keystore, so what is checked here is the
 * contract the runner relies on: every forgery arm names itself, its code
 * routes to the forgery row, and the mask is derived from that code.
 */
class ActiveAttestationProbeTest {

    @Test
    fun theCodesAreTheNextElevenInTheForgeryFamily() {
        assertEquals((1114..1124).toSet(), ActiveAttestationProbe.REASON_CODES)
    }

    @Test
    fun everyCodeRoutesToTheForgeryRow() {
        for (code in ActiveAttestationProbe.REASON_CODES) {
            assertEquals(
                "code $code",
                DetectionResult.DETECTION_ATTEST_FORGERY,
                ReasonCodes.flagOf(code)
            )
        }
    }

    @Test
    fun theMaskIsDerivedFromTheReason() {
        for (code in ActiveAttestationProbe.REASON_CODES) {
            val outcome = ActiveAttestationProbe.Outcome.of(code)
            assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, outcome.mask)
            assertEquals(listOf(code), outcome.reasons)
        }
    }

    /** A code with no row lights nothing, rather than a row it cannot explain. */
    @Test
    fun aCodeWithNoRowLightsNothing() {
        assertEquals(0, ActiveAttestationProbe.Outcome.of(9999).mask)
    }

    @Test
    fun theSoftwareReadoutNamesNoArm() {
        val software = ActiveAttestationProbe.Outcome.SOFTWARE
        assertEquals(DetectionResult.DETECTION_ATTEST_SOFTWARE, software.mask)
        assertTrue(software.reasons.isEmpty())
    }

    @Test
    fun aCleanRunIsSilent() {
        assertEquals(0, ActiveAttestationProbe.Outcome.NONE.mask)
        assertTrue(ActiveAttestationProbe.Outcome.NONE.reasons.isEmpty())
    }

    @Test
    fun theReasonsRenderUnderTheForgeryRow() {
        val reasons = ActiveAttestationProbe.Outcome.of(
            ActiveAttestationProbe.REASON_AUTH_BOUND_AUTH_CONTRADICTION
        ).reasons
        val rows = ReasonCodes.describe(reasons)
        assertEquals(setOf(DetectionResult.DETECTION_ATTEST_FORGERY), rows.keys)
    }
}
