package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The attested identity decision table.
 *
 * The measured baseline on both bench devices, a Samsung TEE and the AOSP
 * software keystore, is the clean row: an ordinary attestation record carries
 * no identifier tag at all, and the device-properties request is refused with
 * CANNOT_ATTEST_IDS. Everything asserted here is a departure from that.
 */
class AttestedIdentityTest {

    private val teeLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    private val strongBoxLevel = AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
    private val softwareLevel = AttestationAnalysis.SECURITY_LEVEL_SOFTWARE

    private fun record(
        hardware: Set<Int> = emptySet(),
        software: Set<Int> = emptySet(),
        level: Int? = teeLevel,
    ) = AttestedIdentity.RecordIds(hardware, software, level)

    private val cleanPlain = record()
    private val refused = AttestedIdentity.PropertiesOutcome(accepted = false, record = null)

    private fun accepted(record: AttestedIdentity.RecordIds?) =
        AttestedIdentity.PropertiesOutcome(accepted = true, record = record)

    private fun evaluate(
        plain: AttestedIdentity.RecordIds? = cleanPlain,
        withProperties: AttestedIdentity.PropertiesOutcome? = refused,
    ) = AttestedIdentity.evaluate(AttestedIdentity.Observation(plain, withProperties))

    // ---- the measured baseline ---------------------------------------------

    @Test
    fun theMeasuredBaselineIsSilent() {
        val verdict = evaluate()
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
        assertFalse(verdict.isFinding)
    }

    /** The AOSP software keystore's row: software level, same clean answer. */
    @Test
    fun anAllSoftwareKeystoreThatRefusesIsEquallyClean() {
        val verdict = evaluate(plain = record(level = softwareLevel), withProperties = refused)
        assertEquals(0, verdict.mask)
    }

    // ---- an identifier nothing asked for -----------------------------------

    @Test
    fun eachDevicePropertyIdentifierInAnOrdinaryRecordIsAFinding() {
        for (tag in AttestedIdentity.DEVICE_PROPERTY_TAGS) {
            val verdict = evaluate(plain = record(hardware = setOf(tag)))
            assertEquals(
                "tag $tag should be reported",
                DetectionResult.DETECTION_ATTEST_FORGERY,
                verdict.mask
            )
            assertEquals(
                "tag $tag",
                listOf(AttestedIdentity.REASON_UNREQUESTED_ID),
                verdict.reasons
            )
        }
    }

    /**
     * Either list counts. Nothing asked for the identifier, so whichever side
     * of the record volunteered it, the record is answering a question it was
     * not asked.
     */
    @Test
    fun anIdentifierInTheSoftwareListOfAnOrdinaryRecordIsAlsoAFinding() {
        val verdict = evaluate(
            plain = record(software = setOf(AttestedIdentity.TAG_ID_MODEL))
        )
        assertEquals(listOf(AttestedIdentity.REASON_UNREQUESTED_ID), verdict.reasons)
    }

    @Test
    fun eachPrivilegedIdentifierIsAFinding() {
        for (tag in AttestedIdentity.PRIVILEGED_TAGS) {
            val verdict = evaluate(plain = record(hardware = setOf(tag)))
            assertEquals(
                "tag $tag should be reported as privileged and nothing else",
                listOf(AttestedIdentity.REASON_PRIVILEGED_ID),
                verdict.reasons
            )
        }
    }

    /** The privileged watch covers the properties record too. */
    @Test
    fun aPrivilegedIdentifierInThePropertiesRecordIsAFinding() {
        val verdict = evaluate(
            withProperties = accepted(
                record(hardware = AttestedIdentity.DEVICE_PROPERTY_TAGS + setOf(
                    AttestedIdentity.TAG_ID_IMEI
                ))
            )
        )
        assertEquals(listOf(AttestedIdentity.REASON_PRIVILEGED_ID), verdict.reasons)
    }

    // ---- the device-properties request -------------------------------------

    @Test
    fun acceptedAndThenAttestingNothingIsAFinding() {
        val verdict = evaluate(withProperties = accepted(record()))
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, verdict.mask)
        assertEquals(listOf(AttestedIdentity.REASON_ACCEPTED_WITHOUT_IDS), verdict.reasons)
    }

    /** The honest answer from a device that supports it: accepted and vouched. */
    @Test
    fun acceptedWithIdentifiersInTheHardwareListIsSilent() {
        val verdict = evaluate(
            withProperties = accepted(record(hardware = AttestedIdentity.DEVICE_PROPERTY_TAGS))
        )
        assertEquals(0, verdict.mask)
    }

    @Test
    fun identifiersOnlyInTheSoftwareListOfAHardwareRecordIsAFinding() {
        val verdict = evaluate(
            withProperties = accepted(
                record(software = AttestedIdentity.DEVICE_PROPERTY_TAGS, level = teeLevel)
            )
        )
        assertEquals(listOf(AttestedIdentity.REASON_IDS_NOT_VOUCHED), verdict.reasons)
    }

    @Test
    fun strongBoxIsHeldToTheSameStandardAsATee() {
        val verdict = evaluate(
            withProperties = accepted(
                record(software = AttestedIdentity.DEVICE_PROPERTY_TAGS, level = strongBoxLevel)
            )
        )
        assertEquals(listOf(AttestedIdentity.REASON_IDS_NOT_VOUCHED), verdict.reasons)
    }

    /**
     * The false positive this arm exists to avoid. On a software-level record
     * the software-enforced list is where every entry legitimately sits, so
     * finding the identifiers there says nothing.
     */
    @Test
    fun aSoftwareLevelRecordKeepsItsIdentifiersInTheSoftwareList() {
        val verdict = evaluate(
            withProperties = accepted(
                record(software = AttestedIdentity.DEVICE_PROPERTY_TAGS, level = softwareLevel)
            )
        )
        assertEquals(0, verdict.mask)
    }

    /** A record with no level claim is not claiming a secure environment. */
    @Test
    fun aRecordWithNoLevelIsNotAccusedOfFailingToVouch() {
        val verdict = evaluate(
            withProperties = accepted(
                record(software = AttestedIdentity.DEVICE_PROPERTY_TAGS, level = null)
            )
        )
        assertEquals(0, verdict.mask)
    }

    /**
     * Partly vouched is vouched. The arm asks whether the secure environment
     * stood behind the identifiers at all, not whether it stood behind each.
     */
    @Test
    fun oneIdentifierInTheHardwareListIsEnoughToBeVouchedFor() {
        val verdict = evaluate(
            withProperties = accepted(
                record(
                    hardware = setOf(AttestedIdentity.TAG_ID_BRAND),
                    software = AttestedIdentity.DEVICE_PROPERTY_TAGS -
                        setOf(AttestedIdentity.TAG_ID_BRAND),
                    level = teeLevel,
                )
            )
        )
        assertEquals(0, verdict.mask)
    }

    // ---- answers that are not evidence -------------------------------------

    /**
     * Accepted with a record this build cannot read. The oldest supported
     * devices emit a KeyDescription the authorization list parser rejects, so
     * treating an unreadable record as "no identifier" would flag them.
     */
    @Test
    fun acceptedWithAnUnreadableRecordSaysNothing() {
        val verdict = evaluate(withProperties = accepted(null))
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
    }

    /** A refusal is the contract's own answer, not a departure from it. */
    @Test
    fun aRefusalSaysNothing() {
        val verdict = evaluate(withProperties = refused)
        assertEquals(0, verdict.mask)
    }

    /**
     * A refusal is not judged even if a record came back with it. The probe
     * reports no record alongside a refusal, so this pins the intent rather
     * than a shape the probe produces: nothing about a request that failed is
     * evidence about a request that succeeded.
     */
    @Test
    fun aRefusalIsNotJudgedEvenWhenItCarriesARecord() {
        val empty = AttestedIdentity.PropertiesOutcome(accepted = false, record = record())
        assertEquals(0, evaluate(withProperties = empty).mask)

        val unvouched = AttestedIdentity.PropertiesOutcome(
            accepted = false,
            record = record(software = AttestedIdentity.DEVICE_PROPERTY_TAGS, level = teeLevel),
        )
        assertEquals(0, evaluate(withProperties = unvouched).mask)
    }

    /**
     * The one question a refusal does not silence. Whether the keystore
     * reported success says nothing about whether this app was handed an
     * identifier it cannot request, so a privileged tag is reported either way.
     */
    @Test
    fun aPrivilegedIdentifierIsReportedEvenAlongsideARefusal() {
        val refusedWithImei = AttestedIdentity.PropertiesOutcome(
            accepted = false,
            record = record(hardware = setOf(AttestedIdentity.TAG_ID_IMEI)),
        )
        assertEquals(
            listOf(AttestedIdentity.REASON_PRIVILEGED_ID),
            evaluate(withProperties = refusedWithImei).reasons
        )
    }

    @Test
    fun anObservationWithNothingInItIsSilent() {
        val verdict = AttestedIdentity.evaluate(AttestedIdentity.Observation())
        assertEquals(0, verdict.mask)
        assertEquals(emptyList<Int>(), verdict.reasons)
    }

    @Test
    fun aMissingOrdinaryRecordDoesNotSuppressTheOtherArm() {
        val verdict = evaluate(plain = null, withProperties = accepted(record()))
        assertEquals(listOf(AttestedIdentity.REASON_ACCEPTED_WITHOUT_IDS), verdict.reasons)
    }

    @Test
    fun aMissingPropertiesArmDoesNotSuppressTheOtherOne() {
        val verdict = evaluate(
            plain = record(hardware = setOf(AttestedIdentity.TAG_ID_BRAND)),
            withProperties = null,
        )
        assertEquals(listOf(AttestedIdentity.REASON_UNREQUESTED_ID), verdict.reasons)
    }

    /** Several departures at once report one line each, so a report names all. */
    @Test
    fun everyDepartureThatFiredIsReportedSeparately() {
        val verdict = evaluate(
            plain = record(
                hardware = setOf(AttestedIdentity.TAG_ID_BRAND, AttestedIdentity.TAG_ID_SERIAL)
            ),
            withProperties = accepted(record()),
        )
        assertEquals(
            listOf(
                AttestedIdentity.REASON_UNREQUESTED_ID,
                AttestedIdentity.REASON_PRIVILEGED_ID,
                AttestedIdentity.REASON_ACCEPTED_WITHOUT_IDS,
            ),
            verdict.reasons
        )
    }

    // ---- the tag numbers themselves ----------------------------------------

    /**
     * Pinned against Tag.aidl. A wrong number here would look at the wrong
     * member of the authorization list and could not fail any other way.
     */
    @Test
    fun theTagNumbersMatchTheSchema() {
        assertEquals(710, AttestedIdentity.TAG_ID_BRAND)
        assertEquals(711, AttestedIdentity.TAG_ID_DEVICE)
        assertEquals(712, AttestedIdentity.TAG_ID_PRODUCT)
        assertEquals(713, AttestedIdentity.TAG_ID_SERIAL)
        assertEquals(714, AttestedIdentity.TAG_ID_IMEI)
        assertEquals(715, AttestedIdentity.TAG_ID_MEID)
        assertEquals(716, AttestedIdentity.TAG_ID_MANUFACTURER)
        assertEquals(717, AttestedIdentity.TAG_ID_MODEL)
        assertEquals(723, AttestedIdentity.TAG_ID_SECOND_IMEI)
    }

    /** Exactly the five the framework requests, and no more. */
    @Test
    fun theDevicePropertySetIsWhatTheFrameworkRequests() {
        assertEquals(setOf(710, 711, 712, 716, 717), AttestedIdentity.DEVICE_PROPERTY_TAGS)
    }

    @Test
    fun thePrivilegedSetIsTheIdentifiersThisAppCannotAskFor() {
        assertEquals(setOf(713, 714, 715, 723), AttestedIdentity.PRIVILEGED_TAGS)
    }

    /** A tag belongs to one arm, so the two sets may not overlap. */
    @Test
    fun theTwoSetsAreDisjointAndTogetherAreAllOfThem() {
        assertEquals(
            emptySet<Int>(),
            AttestedIdentity.DEVICE_PROPERTY_TAGS.intersect(AttestedIdentity.PRIVILEGED_TAGS)
        )
        assertEquals(
            AttestedIdentity.DEVICE_PROPERTY_TAGS + AttestedIdentity.PRIVILEGED_TAGS,
            AttestedIdentity.ALL_ID_TAGS
        )
        assertEquals(9, AttestedIdentity.ALL_ID_TAGS.size)
    }

    @Test
    fun theVouchedPredicateAgreesWithTheLevel() {
        assertTrue(record(level = teeLevel).vouchedBySecureEnvironment)
        assertTrue(record(level = strongBoxLevel).vouchedBySecureEnvironment)
        assertFalse(record(level = softwareLevel).vouchedBySecureEnvironment)
        assertFalse(record(level = null).vouchedBySecureEnvironment)
    }

    @Test
    fun allCollapsesBothLists() {
        val both = record(hardware = setOf(710), software = setOf(717))
        assertEquals(setOf(710, 717), both.all)
    }

    // ---- the codes themselves ----------------------------------------------

    /**
     * Every declared code must be producible by some observation, otherwise it
     * is text that can never appear. Two observations are needed because
     * attesting nothing and attesting unvouched identifiers are mutually
     * exclusive shapes.
     */
    @Test
    fun everyDeclaredCodeIsReachable() {
        val emitted = listOf(
            evaluate(
                plain = record(
                    hardware = setOf(
                        AttestedIdentity.TAG_ID_BRAND, AttestedIdentity.TAG_ID_SERIAL
                    )
                ),
                withProperties = accepted(record()),
            ),
            evaluate(
                withProperties = accepted(
                    record(software = AttestedIdentity.DEVICE_PROPERTY_TAGS, level = teeLevel)
                )
            ),
        ).flatMap { it.reasons }.toSet()

        assertEquals(AttestedIdentity.REASON_CODES, emitted)
    }

    @Test
    fun everyReasonTheTableEmitsRoutesToTheForgeryRow() {
        val described = ReasonCodes.describe(AttestedIdentity.REASON_CODES.toList())
        assertEquals(setOf(DetectionResult.DETECTION_ATTEST_FORGERY), described.keys)
        assertEquals(AttestedIdentity.REASON_CODES.size, described.values.sumOf { it.size })
    }

    /** A reason must land on the row whose bit the verdict sets. */
    @Test
    fun theReasonsLandOnTheRowTheMaskLightsUp() {
        val verdict = evaluate(plain = record(hardware = setOf(AttestedIdentity.TAG_ID_BRAND)))
        val rows = DetectionResult.fromBitmask(verdict.mask, reasonCodes = verdict.reasons)
        val forgery = rows.first { it.flag == DetectionResult.DETECTION_ATTEST_FORGERY }

        assertTrue(forgery.detected)
        assertEquals(1, forgery.reasons.size)
        assertTrue(forgery.reasons.single().contains("nothing asked it to attest"))
        assertTrue(
            "a reason must not leak onto a row it does not explain",
            rows.filter { it.flag != DetectionResult.DETECTION_ATTEST_FORGERY }
                .all { it.reasons.isEmpty() }
        )
    }

    /** The boundary probe and this one must not both claim a code. */
    @Test
    fun theCodesDoNotCollideWithTheBoundaryProbe() {
        assertEquals(
            emptySet<Int>(),
            AttestedIdentity.REASON_CODES.intersect(KeystoreBoundary.REASON_CODES)
        )
    }
}
