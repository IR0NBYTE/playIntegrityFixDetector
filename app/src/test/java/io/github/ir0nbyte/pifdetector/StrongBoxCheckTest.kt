package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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

    private companion object {
        /** What the bench Pixel 7a declares, measured. */
        const val PIXEL_FEATURE_VERSION = 300
    }

    private val teeLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    private val strongBoxLevel = AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
    private val softwareLevel = AttestationAnalysis.SECURITY_LEVEL_SOFTWARE

    private fun record(
        attestation: Int? = teeLevel,
        keyMint: Int? = teeLevel,
    ) = StrongBoxCheck.Record(attestation, keyMint)

    private fun evaluate(
        featureDeclared: Boolean? = false,
        strongBoxFeatureVersion: Int? = 0,
        availability: StrongBoxCheck.Availability? = StrongBoxCheck.Availability.UNAVAILABLE,
        ordinaryKeyLevel: Int? = teeLevel,
        ordinaryRecord: StrongBoxCheck.Record? = record(),
        aes192: StrongBoxCheck.AesOutcome? = StrongBoxCheck.AesOutcome.UNAVAILABLE,
    ) = StrongBoxCheck.evaluate(
        StrongBoxCheck.Observation(
            featureDeclared, strongBoxFeatureVersion, availability,
            ordinaryKeyLevel, ordinaryRecord, aes192,
        )
    )

    /**
     * The measured Pixel 7a: declares StrongBox at feature version 300, serves
     * it, and refuses the AES size its HAL forbids.
     */
    private fun honestStrongBox(
        aes192: StrongBoxCheck.AesOutcome = StrongBoxCheck.AesOutcome.REFUSED,
        strongBoxFeatureVersion: Int? = PIXEL_FEATURE_VERSION,
    ) = evaluate(
        featureDeclared = true,
        strongBoxFeatureVersion = strongBoxFeatureVersion,
        availability = StrongBoxCheck.Availability.SERVED,
        ordinaryKeyLevel = teeLevel,
        ordinaryRecord = record(),
        aes192 = aes192,
    )

    // ---- the measured baseline ---------------------------------------------

    @Test
    fun theMeasuredBaselineIsSilent() {
        val verdict = evaluate()
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
        assertFalse(verdict.isFinding)
    }

    /**
     * A genuine StrongBox device that declares it, serves it and refuses the
     * size a secure element must refuse is clean.
     */
    @Test
    fun aDeviceThatDeclaresStrongBoxAndServesItIsSilent() {
        assertEquals(0, honestStrongBox().mask)
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

    // ---- the AES size restriction ------------------------------------------

    @Test
    fun aStrongBoxThatTakesAOneHundredAndNinetyTwoBitAesKeyIsAFinding() {
        val verdict = honestStrongBox(aes192 = StrongBoxCheck.AesOutcome.ACCEPTED)
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(StrongBoxCheck.REASON_STRONGBOX_TOOK_AES_192), verdict.reasons)
    }

    /**
     * The review's first required change, pinned: the finding is acceptance,
     * never refusal. Refusing is what a genuine secure element does.
     */
    @Test
    fun refusingThatSizeIsTheHonestAnswerAndNeverAFinding() {
        assertEquals(0, honestStrongBox(aes192 = StrongBoxCheck.AesOutcome.REFUSED).mask)
    }

    /**
     * Acceptance only means something once the keystore has actually served a
     * StrongBox key. Without that, the AES request was turned away because
     * there is no secure element, not because of a key size.
     */
    @Test
    fun anAcceptedAesKeyIsNotJudgedWhereThereIsNoStrongBox() {
        for (availability in listOf(
            StrongBoxCheck.Availability.UNAVAILABLE,
            StrongBoxCheck.Availability.INCONCLUSIVE,
            null,
        )) {
            val verdict = evaluate(
                availability = availability,
                aes192 = StrongBoxCheck.AesOutcome.ACCEPTED,
                strongBoxFeatureVersion = PIXEL_FEATURE_VERSION,
            )
            assertEquals(
                "availability $availability does not license the AES arm",
                0,
                verdict.mask
            )
        }
    }

    /**
     * A probe whose own request was rejected locally must not read as a pass.
     * The outcome is kept distinct from a refusal precisely so this cannot
     * become a dead arm reporting clean.
     */
    @Test
    fun anArmThatNeverRanIsNotTreatedAsARefusal() {
        for (outcome in listOf(
            StrongBoxCheck.AesOutcome.NOT_ATTEMPTED,
            StrongBoxCheck.AesOutcome.UNAVAILABLE,
            null,
        )) {
            assertEquals(0, honestStrongBox(aes192 = outcome ?: StrongBoxCheck.AesOutcome.UNAVAILABLE).mask)
        }
        assertNotEquals(
            "a refusal and an arm that did not run must not be the same value",
            StrongBoxCheck.AesOutcome.REFUSED,
            StrongBoxCheck.AesOutcome.NOT_ATTEMPTED
        )
    }

    /** The AES arm and the claim arms are independent, so both can fire. */
    @Test
    fun theAesArmAndTheUndeclaredArmAreReportedSeparately() {
        val verdict = evaluate(
            featureDeclared = false,
            strongBoxFeatureVersion = PIXEL_FEATURE_VERSION,
            availability = StrongBoxCheck.Availability.SERVED,
            aes192 = StrongBoxCheck.AesOutcome.ACCEPTED,
        )
        assertEquals(
            listOf(
                StrongBoxCheck.REASON_UNDECLARED_STRONGBOX,
                StrongBoxCheck.REASON_STRONGBOX_TOOK_AES_192,
            ),
            verdict.reasons
        )
    }

    /** The size asked for is the one value the KeyMint HAL leaves no room for. */
    @Test
    fun theForbiddenSizeIsTheOneBetweenTheTwoRequiredOnes() {
        assertEquals(192, StrongBoxCheck.AES_FORBIDDEN_SIZE_BITS)
    }

    /**
     * MEASURED on the phone station, and the reason the gate exists. A stock,
     * locked Samsung SM-G780G declaring strongbox_keystore=4 serves StrongBox
     * and accepts a 192 bit AES key. It implements Keymaster 4.0, whose HAL
     * lists AES as "128 and 256-bit keys" with no StrongBox clause at all, so
     * it was never told to refuse the size. Reporting it would be a false
     * positive on a genuine retail handset.
     */
    @Test
    fun aKeymasterEraSecureElementThatTakesTheSizeIsNotAFinding() {
        for (version in listOf(0, 4, 40, 41, 99)) {
            val verdict = honestStrongBox(
                aes192 = StrongBoxCheck.AesOutcome.ACCEPTED,
                strongBoxFeatureVersion = version,
            )
            assertEquals(
                "strongbox_keystore=$version predates the AES restriction",
                0,
                verdict.mask
            )
        }
    }

    /** From KeyMint 1.0 the restriction exists, so acceptance is a finding. */
    @Test
    fun aKeyMintSecureElementThatTakesTheSizeIsAFinding() {
        for (version in listOf(100, 200, 300, 400)) {
            val verdict = honestStrongBox(
                aes192 = StrongBoxCheck.AesOutcome.ACCEPTED,
                strongBoxFeatureVersion = version,
            )
            assertEquals(
                "strongbox_keystore=$version carries the AES restriction",
                listOf(StrongBoxCheck.REASON_STRONGBOX_TOOK_AES_192),
                verdict.reasons
            )
        }
    }

    /** An unreadable feature list is not a licence to judge the size. */
    @Test
    fun anUnknownStrongBoxVersionIsNeverJudged() {
        val verdict = honestStrongBox(
            aes192 = StrongBoxCheck.AesOutcome.ACCEPTED,
            strongBoxFeatureVersion = null,
        )
        assertEquals(0, verdict.mask)
    }

    /** The gate is pinned to the version the restriction arrived in. */
    @Test
    fun theGateIsTheFirstKeyMintFeatureVersion() {
        assertEquals(100, StrongBoxCheck.STRONGBOX_FEATURE_VERSION_KEYMINT_1)
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
            evaluate(
                availability = StrongBoxCheck.Availability.SERVED,
                aes192 = StrongBoxCheck.AesOutcome.ACCEPTED,
                strongBoxFeatureVersion = PIXEL_FEATURE_VERSION,
            ),
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
    fun theCodesAreTheNextFourInTheForgeryFamily() {
        assertEquals(listOf(1109, 1110, 1111, 1112), StrongBoxCheck.REASON_CODES.sorted())
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
