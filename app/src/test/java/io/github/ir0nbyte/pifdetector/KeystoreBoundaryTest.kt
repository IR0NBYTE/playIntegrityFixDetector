package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The boundary decision table.
 *
 * The measured baseline on both bench devices, a Samsung TEE and the AOSP
 * software keystore, is the clean row: a no-challenge key comes back as a
 * self-signed certificate with no attestation record, and a 129 byte challenge
 * is refused with INVALID_INPUT_LENGTH. Everything asserted here is a departure
 * from that.
 */
class KeystoreBoundaryTest {

    private val cleanNoChallenge =
        KeystoreBoundary.NoChallengeShape(selfSigned = true, carriesAttestationRecord = false)
    private val refused =
        KeystoreBoundary.ChallengeOutcome(accepted = false, securityLevel = null)
    private val acceptedInHardware = KeystoreBoundary.ChallengeOutcome(
        accepted = true,
        securityLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    )
    private val acceptedInStrongBox = KeystoreBoundary.ChallengeOutcome(
        accepted = true,
        securityLevel = AttestationAnalysis.SECURITY_LEVEL_STRONGBOX,
    )
    private val acceptedInSoftware = KeystoreBoundary.ChallengeOutcome(
        accepted = true,
        securityLevel = AttestationAnalysis.SECURITY_LEVEL_SOFTWARE,
    )
    private val acceptedWithNoRecord =
        KeystoreBoundary.ChallengeOutcome(accepted = true, securityLevel = null)

    private fun evaluate(
        noChallenge: KeystoreBoundary.NoChallengeShape? = cleanNoChallenge,
        legal: KeystoreBoundary.ChallengeOutcome? = acceptedInHardware,
        overLimit: KeystoreBoundary.ChallengeOutcome? = refused,
    ) = KeystoreBoundary.evaluate(
        KeystoreBoundary.Observation(noChallenge, legal, overLimit)
    )

    // ---- the measured baseline ---------------------------------------------

    @Test
    fun theMeasuredBaselineIsSilent() {
        val verdict = evaluate()
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
        assertFalse(verdict.isFinding)
    }

    /** A software keystore refusing the over-limit request is equally clean. */
    @Test
    fun anAllSoftwareDeviceThatHonoursTheContractIsSilent() {
        val verdict = evaluate(legal = acceptedInSoftware, overLimit = refused)
        assertEquals(0, verdict.mask)
    }

    // ---- no challenge ------------------------------------------------------

    @Test
    fun anAttestationRecordWithNoChallengeIsAFinding() {
        val verdict = evaluate(
            noChallenge = KeystoreBoundary.NoChallengeShape(
                selfSigned = true, carriesAttestationRecord = true
            )
        )
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(KeystoreBoundary.REASON_NO_CHALLENGE_RECORD), verdict.reasons)
    }

    @Test
    fun aNonSelfSignedNoChallengeCertificateIsAFinding() {
        val verdict = evaluate(
            noChallenge = KeystoreBoundary.NoChallengeShape(
                selfSigned = false, carriesAttestationRecord = false
            )
        )
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(KeystoreBoundary.REASON_NO_CHALLENGE_NOT_SELF_SIGNED), verdict.reasons)
    }

    /** Both wrong at once reports both, so the report names each arm. */
    @Test
    fun bothNoChallengeDeparturesAreReportedSeparately() {
        val verdict = evaluate(
            noChallenge = KeystoreBoundary.NoChallengeShape(
                selfSigned = false, carriesAttestationRecord = true
            )
        )
        assertEquals(
            listOf(
                KeystoreBoundary.REASON_NO_CHALLENGE_RECORD,
                KeystoreBoundary.REASON_NO_CHALLENGE_NOT_SELF_SIGNED,
            ),
            verdict.reasons
        )
    }

    // ---- the challenge length limit ----------------------------------------

    @Test
    fun acceptingAnOverLimitChallengeIsAFinding() {
        val verdict = evaluate(overLimit = acceptedInHardware)
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED), verdict.reasons)
    }

    /**
     * The documented simulator behaviour: the over-limit request is accepted
     * and quietly served from software while a legal one came from hardware.
     */
    @Test
    fun anOverLimitRequestServedFromSoftwareAlsoReportsTheDowngrade() {
        val verdict = evaluate(legal = acceptedInHardware, overLimit = acceptedInSoftware)
        assertEquals(
            listOf(
                KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED,
                KeystoreBoundary.REASON_OVER_LIMIT_DOWNGRADED,
            ),
            verdict.reasons
        )
    }

    /**
     * A device that is software-backed throughout has not downgraded anything,
     * so only the length departure is claimed.
     */
    @Test
    fun aSoftwareOnlyDeviceIsNotAccusedOfDowngrading() {
        val verdict = evaluate(legal = acceptedInSoftware, overLimit = acceptedInSoftware)
        assertEquals(listOf(KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED), verdict.reasons)
    }

    /** No baseline means no downgrade claim: there is nothing to compare to. */
    @Test
    fun withoutALegalBaselineTheDowngradeIsNotClaimed() {
        val verdict = evaluate(legal = null, overLimit = acceptedInSoftware)
        assertEquals(listOf(KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED), verdict.reasons)
    }

    /** A refused legal challenge is also no baseline. */
    @Test
    fun aRefusedLegalChallengeIsNotABaselineEither() {
        val verdict = evaluate(legal = refused, overLimit = acceptedInSoftware)
        assertEquals(listOf(KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED), verdict.reasons)
    }

    /**
     * Accepted but with no record at all is not a downgrade. Only the length
     * departure is claimed, because nothing said software.
     */
    @Test
    fun anAcceptedRequestWithNoRecordIsNotCalledADowngrade() {
        val verdict = evaluate(legal = acceptedInHardware, overLimit = acceptedWithNoRecord)
        assertEquals(listOf(KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED), verdict.reasons)
    }

    /** StrongBox counts as a hardware baseline, same as a TEE. */
    @Test
    fun aStrongBoxBaselineIsAHardwareBaseline() {
        val verdict = evaluate(legal = acceptedInStrongBox, overLimit = acceptedInSoftware)
        assertEquals(
            listOf(
                KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED,
                KeystoreBoundary.REASON_OVER_LIMIT_DOWNGRADED,
            ),
            verdict.reasons
        )
    }

    @Test
    fun theLevelPredicatesAgreeWithTheLevel() {
        assertTrue(acceptedInHardware.hardwareBacked)
        assertTrue(acceptedInStrongBox.hardwareBacked)
        assertFalse(acceptedInSoftware.hardwareBacked)
        assertTrue(acceptedInSoftware.softwareBacked)
        assertFalse(acceptedWithNoRecord.hardwareBacked)
        assertFalse("no record must not read as software", acceptedWithNoRecord.softwareBacked)
    }

    @Test
    fun theMaximumIsTheDocumentedOneHundredAndTwentyEight() {
        assertEquals(128, KeystoreBoundary.MAX_CHALLENGE_BYTES)
    }

    // ---- arms that could not run -------------------------------------------

    /** An arm that could not run says nothing rather than guessing. */
    @Test
    fun anObservationWithNothingInItIsSilent() {
        val verdict = KeystoreBoundary.evaluate(KeystoreBoundary.Observation())
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
    }

    @Test
    fun aMissingNoChallengeArmDoesNotSuppressTheOtherOne() {
        val verdict = evaluate(noChallenge = null, overLimit = acceptedInHardware)
        assertEquals(listOf(KeystoreBoundary.REASON_OVER_LIMIT_ACCEPTED), verdict.reasons)
    }

    @Test
    fun aMissingOverLimitArmDoesNotSuppressTheOtherOne() {
        val verdict = evaluate(
            noChallenge = KeystoreBoundary.NoChallengeShape(
                selfSigned = true, carriesAttestationRecord = true
            ),
            overLimit = null,
        )
        assertEquals(listOf(KeystoreBoundary.REASON_NO_CHALLENGE_RECORD), verdict.reasons)
    }

    // ---- the codes themselves ---------------------------------------------

    /**
     * Every declared code must be producible by some observation, otherwise it
     * is text that can never appear. The sync test checks the table has text
     * for each; this checks the probe can actually emit each.
     */
    @Test
    fun everyDeclaredCodeIsReachable() {
        val emitted = listOf(
            evaluate(
                noChallenge = KeystoreBoundary.NoChallengeShape(
                    selfSigned = false, carriesAttestationRecord = true
                ),
                legal = acceptedInHardware,
                overLimit = acceptedInSoftware,
            )
        ).flatMap { it.reasons }.toSet()

        assertEquals(KeystoreBoundary.REASON_CODES, emitted)
    }

    @Test
    fun everyReasonTheTableEmitsRoutesToTheForgeryRow() {
        val described = ReasonCodes.describe(KeystoreBoundary.REASON_CODES.toList())
        assertEquals(setOf(DetectionResult.DETECTION_ATTEST_FORGERY), described.keys)
        assertEquals(KeystoreBoundary.REASON_CODES.size, described.values.sumOf { it.size })
    }

    /** A reason must land on the row whose bit the verdict sets. */
    @Test
    fun theReasonsLandOnTheRowTheMaskLightsUp() {
        val verdict = evaluate(overLimit = acceptedInHardware)
        val rows = DetectionResult.fromBitmask(verdict.mask, reasonCodes = verdict.reasons)
        val forgery = rows.first { it.flag == DetectionResult.DETECTION_ATTEST_FORGERY }

        assertTrue(forgery.detected)
        assertEquals(1, forgery.reasons.size)
        assertTrue(forgery.reasons.single().contains("128 byte"))
        assertTrue(
            "a reason must not leak onto a row it does not explain",
            rows.filter { it.flag != DetectionResult.DETECTION_ATTEST_FORGERY }
                .all { it.reasons.isEmpty() }
        )
    }
}
