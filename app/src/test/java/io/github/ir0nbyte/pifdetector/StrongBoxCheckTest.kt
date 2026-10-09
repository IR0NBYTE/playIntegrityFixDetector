package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The StrongBox decision table.
 *
 * The measured baseline on both bench devices, a Samsung TEE and the AOSP
 * software keystore on API 34, is the clean row: no strongbox_keystore feature,
 * the StrongBox request refused with StrongBoxUnavailableException, and neither
 * the keystore's label on the ordinary key nor either of the record's two level
 * fields naming StrongBox. Everything asserted here is a departure from that.
 */
class StrongBoxCheckTest {

    private val teeLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    private val strongBoxLevel = AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
    private val softwareLevel = AttestationAnalysis.SECURITY_LEVEL_SOFTWARE

    private fun record(
        attestation: Int? = teeLevel,
        keyMint: Int? = teeLevel,
    ) = StrongBoxCheck.Record(attestation, keyMint)

    private fun evaluate(
        featureDeclared: Boolean? = false,
        availability: StrongBoxCheck.Availability? = StrongBoxCheck.Availability.UNAVAILABLE,
        ordinaryKeyLevel: Int? = teeLevel,
        ordinaryRecord: StrongBoxCheck.Record? = record(),
    ) = StrongBoxCheck.evaluate(
        StrongBoxCheck.Observation(
            featureDeclared, availability, ordinaryKeyLevel, ordinaryRecord
        )
    )

    // ---- the measured baseline ---------------------------------------------

    @Test
    fun theMeasuredBaselineIsSilent() {
        val verdict = evaluate()
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
        assertFalse(verdict.isFinding)
    }

    /** A genuine StrongBox device that declares it and serves it is clean. */
    @Test
    fun aDeviceThatDeclaresStrongBoxAndServesItIsSilent() {
        val verdict = evaluate(
            featureDeclared = true,
            availability = StrongBoxCheck.Availability.SERVED,
            ordinaryKeyLevel = teeLevel,
            ordinaryRecord = record(),
        )
        assertEquals(0, verdict.mask)
    }

    /** An emulator attesting at software level throughout is clean too. */
    @Test
    fun anAllSoftwareDeviceIsSilent() {
        val verdict = evaluate(
            ordinaryKeyLevel = softwareLevel,
            ordinaryRecord = record(attestation = softwareLevel, keyMint = softwareLevel),
        )
        assertEquals(0, verdict.mask)
    }

    // ---- a StrongBox claim with no StrongBox -------------------------------

    @Test
    fun aKeyLabelledStrongBoxWhereThereIsNoStrongBoxIsAFinding() {
        val verdict = evaluate(ordinaryKeyLevel = strongBoxLevel)
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(StrongBoxCheck.REASON_KEY_IN_ABSENT_STRONGBOX), verdict.reasons)
    }

    @Test
    fun aRecordClaimingStrongBoxWhereThereIsNoStrongBoxIsAFinding() {
        val verdict = evaluate(ordinaryRecord = record(attestation = strongBoxLevel))
        assertEquals(
            listOf(StrongBoxCheck.REASON_RECORD_CLAIMS_ABSENT_STRONGBOX),
            verdict.reasons
        )
    }

    /** Either of the record's two level fields counts as the claim. */
    @Test
    fun theKeyMintFieldClaimingStrongBoxCountsToo() {
        val verdict = evaluate(ordinaryRecord = record(keyMint = strongBoxLevel))
        assertEquals(
            listOf(StrongBoxCheck.REASON_RECORD_CLAIMS_ABSENT_STRONGBOX),
            verdict.reasons
        )
    }

    /** The label and the record are separate statements, so both get reported. */
    @Test
    fun bothClaimsAreReportedSeparately() {
        val verdict = evaluate(
            ordinaryKeyLevel = strongBoxLevel,
            ordinaryRecord = record(attestation = strongBoxLevel, keyMint = strongBoxLevel),
        )
        assertEquals(
            listOf(
                StrongBoxCheck.REASON_KEY_IN_ABSENT_STRONGBOX,
                StrongBoxCheck.REASON_RECORD_CLAIMS_ABSENT_STRONGBOX,
            ),
            verdict.reasons
        )
    }

    /**
     * The arm needs keystore2 to have said there is no StrongBox. On a device
     * that has one, a StrongBox claim is just true.
     */
    @Test
    fun aStrongBoxClaimOnAStrongBoxDeviceIsNotAFinding() {
        val verdict = evaluate(
            featureDeclared = true,
            availability = StrongBoxCheck.Availability.SERVED,
            ordinaryKeyLevel = strongBoxLevel,
            ordinaryRecord = record(attestation = strongBoxLevel, keyMint = strongBoxLevel),
        )
        assertEquals(0, verdict.mask)
    }

    /**
     * The review's constraint, pinned: a StrongBox request that failed for some
     * reason other than the hardware being absent proves nothing, because a
     * genuine device can be out of remotely provisioned keys. Even a StrongBox
     * claim alongside it is not reported.
     */
    @Test
    fun anInconclusiveRequestNeverLicensesAFinding() {
        val verdict = evaluate(
            availability = StrongBoxCheck.Availability.INCONCLUSIVE,
            ordinaryKeyLevel = strongBoxLevel,
            ordinaryRecord = record(attestation = strongBoxLevel),
        )
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
    }

    /** A refusal on its own is the contract being honoured, never a finding. */
    @Test
    fun aRefusalAloneIsNotAFinding() {
        val verdict = evaluate(featureDeclared = true)
        assertEquals(
            "a device that declares StrongBox and then refuses may be out of " +
                "remotely provisioned keys",
            0,
            verdict.mask
        )
    }

    // ---- served without declaring ------------------------------------------

    @Test
    fun servingStrongBoxWithoutDeclaringItIsAFinding() {
        val verdict = evaluate(availability = StrongBoxCheck.Availability.SERVED)
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(StrongBoxCheck.REASON_UNDECLARED_STRONGBOX), verdict.reasons)
    }

    /** An unreadable feature list is not a declaration of absence. */
    @Test
    fun anUnknownFeatureListDoesNotAccuse() {
        val verdict = evaluate(
            featureDeclared = null,
            availability = StrongBoxCheck.Availability.SERVED,
        )
        assertEquals(0, verdict.mask)
    }

    /** Nor is a refusal on an undeclared device, which is the normal case. */
    @Test
    fun anUndeclaredDeviceThatRefusesIsTheNormalCase() {
        val verdict = evaluate(
            featureDeclared = false,
            availability = StrongBoxCheck.Availability.UNAVAILABLE,
        )
        assertEquals(0, verdict.mask)
    }

    // ---- arms that could not run -------------------------------------------

    @Test
    fun anObservationWithNothingInItIsSilent() {
        val verdict = StrongBoxCheck.evaluate(StrongBoxCheck.Observation())
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
    }

    /** Below API 28 there is no StrongBox API, so no arm may speak. */
    @Test
    fun withoutTheAvailabilityArmNoStrongBoxClaimIsJudged() {
        val verdict = evaluate(
            availability = null,
            ordinaryKeyLevel = strongBoxLevel,
            ordinaryRecord = record(attestation = strongBoxLevel),
        )
        assertEquals(0, verdict.mask)
    }

    /** Below API 31 the key label is unreadable, which must not silence the rest. */
    @Test
    fun aMissingKeyLabelDoesNotSuppressTheRecordArm() {
        val verdict = evaluate(
            ordinaryKeyLevel = null,
            ordinaryRecord = record(attestation = strongBoxLevel),
        )
        assertEquals(
            listOf(StrongBoxCheck.REASON_RECORD_CLAIMS_ABSENT_STRONGBOX),
            verdict.reasons
        )
    }

    @Test
    fun aMissingRecordDoesNotSuppressTheKeyLabelArm() {
        val verdict = evaluate(ordinaryRecord = null, ordinaryKeyLevel = strongBoxLevel)
        assertEquals(listOf(StrongBoxCheck.REASON_KEY_IN_ABSENT_STRONGBOX), verdict.reasons)
    }

    // ---- the codes themselves ---------------------------------------------

    /**
     * Every declared code must be producible by some observation, otherwise it
     * is text that can never appear. Two observations are needed because the
     * undeclared arm requires a served request and the absent-StrongBox arms
     * require a refused one, which no single run can be.
     */
    @Test
    fun everyDeclaredCodeIsReachable() {
        val emitted = listOf(
            evaluate(
                ordinaryKeyLevel = strongBoxLevel,
                ordinaryRecord = record(attestation = strongBoxLevel),
            ),
            evaluate(availability = StrongBoxCheck.Availability.SERVED),
        ).flatMap { it.reasons }.toSet()

        assertEquals(StrongBoxCheck.REASON_CODES, emitted)
    }

    @Test
    fun everyReasonTheTableEmitsRoutesToTheForgeryRow() {
        val described = ReasonCodes.describe(StrongBoxCheck.REASON_CODES.toList())
        assertEquals(setOf(DetectionResult.DETECTION_ATTEST_FORGERY), described.keys)
        assertEquals(StrongBoxCheck.REASON_CODES.size, described.values.sumOf { it.size })
    }

    /** A reason must land on the row whose bit the verdict sets. */
    @Test
    fun theReasonsLandOnTheRowTheMaskLightsUp() {
        val verdict = evaluate(ordinaryKeyLevel = strongBoxLevel)
        val rows = DetectionResult.fromBitmask(verdict.mask, reasonCodes = verdict.reasons)
        val forgery = rows.first { it.flag == DetectionResult.DETECTION_ATTEST_FORGERY }

        assertTrue(forgery.detected)
        assertEquals(1, forgery.reasons.size)
        assertTrue(forgery.reasons.single().contains("no StrongBox instance"))
        assertTrue(
            "a reason must not leak onto a row it does not explain",
            rows.filter { it.flag != DetectionResult.DETECTION_ATTEST_FORGERY }
                .all { it.reasons.isEmpty() }
        )
    }

    /** The codes continue the forgery family rather than starting a new one. */
    @Test
    fun theCodesAreTheNextThreeInTheForgeryFamily() {
        assertEquals(listOf(1109, 1110, 1111), StrongBoxCheck.REASON_CODES.sorted())
    }

    /**
     * Both of a record's stated levels are read, and neither is compared to the
     * other. Only the attestation version 400 schema requires them to match and
     * no attached device emits one, so the comparison is unbuilt and recorded
     * in docs/COVERAGE.md rather than shipped unwitnessed.
     */
    @Test
    fun aMismatchBetweenTheTwoStatedLevelsIsNotJudged() {
        for (pair in listOf(teeLevel to softwareLevel, softwareLevel to teeLevel)) {
            val verdict = evaluate(
                ordinaryRecord = record(attestation = pair.first, keyMint = pair.second)
            )
            assertEquals("levels $pair are not compared to each other", 0, verdict.mask)
        }
    }

    /** The StrongBox level is the one the ASN.1 enumeration gives it. */
    @Test
    fun theStrongBoxLevelIsTwo() {
        assertEquals(2, AttestationAnalysis.SECURITY_LEVEL_STRONGBOX)
    }

    @Test
    fun theRecordPredicateAgreesWithTheLevels() {
        assertTrue(record(attestation = strongBoxLevel).claimsStrongBox)
        assertTrue(record(keyMint = strongBoxLevel).claimsStrongBox)
        assertFalse(record().claimsStrongBox)
        assertFalse(record(attestation = null, keyMint = null).claimsStrongBox)
    }
}
