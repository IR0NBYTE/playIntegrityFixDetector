package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The order arm is the reason this check exists in a reduced form. A genuine
 * retail Motorola Edge (2022) emits a descending hardware-enforced list and
 * passes Google's own attestation verifier, so order is reported and never
 * called.
 */
class RecordShapeTest {

    /** The measured Motorola Edge (2022) hardware-enforced list, KeyMint 1.0. */
    private val motorolaEdge2022 = listOf(
        1, 2, 3, 5, 10, 503, 702, 704, 705, 706, 717, 716, 712, 711, 710, 718, 719
    )

    /** A well-formed ascending list of the shape AOSP emits. */
    private val conforming = listOf(1, 2, 3, 5, 10, 503, 702, 704, 705, 706, 718, 719)

    /**
     * The measured genuine record descends only across the attestation-ID
     * block, which is exactly the span the order readout exempts, so it comes
     * out completely clean: not a finding and not even a warning.
     */
    @Test
    fun theMotorolaEdgeRecordIsClean() {
        val v = evaluate(hardware = motorolaEdge2022)
        assertFalse("a stock retail phone must not be flagged", v.isFinding)
        assertFalse("the ID block is exempt, so not even a warning", v.listOutOfOrder)

        val row = row(v)
        assertFalse(row.detected)
        assertFalse(row.warning)
    }

    /**
     * Out-of-order outside the ID block is reported in the detail only. It must
     * not set the warning state: that renders the revocation-specific wording
     * and would turn the status card amber for behaviour genuine retail devices
     * exhibit.
     */
    @Test
    fun outOfOrderOutsideTheIdBlockIsReportedInTheDetailOnly() {
        val v = evaluate(hardware = listOf(1, 2, 3, 10, 5, 702, 704, 705, 706, 718, 719))
        assertTrue(v.listOutOfOrder)
        assertFalse(v.isFinding)

        val row = row(v)
        assertFalse(row.detected)
        assertFalse(row.warning)
        assertFalse(row.inconclusive)
        assertTrue(row.detail!!.contains("genuine retail devices also emit"))
    }

    @Test
    fun aConformingRecordIsClean() {
        val v = evaluate(hardware = conforming, software = listOf(701, 709))
        assertFalse(v.isFinding)
        assertFalse(v.listOutOfOrder)
        assertFalse(row(v).detected)
    }

    /** One field per tag makes a repeat impossible for a conforming encoder. */
    @Test
    fun aDuplicatedSchemaTagIsAFinding() {
        val v = evaluate(hardware = conforming + listOf(706))
        assertTrue(v.duplicateSchemaTag)
        assertTrue(v.isFinding)
        assertTrue(v.offendingTags.contains(706))
        assertTrue(row(v).detail!!.contains("twice"))
    }

    /** A duplicated vendor-private tag is not something this project can judge. */
    @Test
    fun aDuplicatedUnknownTagIsNotAFinding() {
        val v = evaluate(hardware = conforming + listOf(9001, 9001))
        assertFalse(v.duplicateSchemaTag)
        assertFalse(v.isFinding)
        assertTrue(v.unknownTagPresent)
    }

    @Test
    fun aNeverAttestedTagIsAFinding() {
        assertTrue(evaluate(hardware = conforming + listOf(700)).isFinding)
        assertTrue(evaluate(software = listOf(701, 501)).isFinding)
    }

    /**
     * 600, 601 and 502 are schema-legal for the Keymaster era and AOSP's own
     * legacy encoder still emits them, so they are not in the never-attested
     * set.
     */
    @Test
    fun legacySchemaTagsAreNotNeverAttested() {
        assertFalse(evaluate(hardware = conforming + listOf(600)).isFinding)
        assertFalse(evaluate(hardware = conforming + listOf(601)).isFinding)
        assertFalse(evaluate(hardware = conforming + listOf(502)).isFinding)
    }

    @Test
    fun aHardwareOnlyTagInTheSoftwareListIsAFinding() {
        val v = evaluate(hardware = conforming, software = listOf(701, 704))
        assertTrue(v.hardwareOnlyTagInSoftwareList)
        assertTrue(v.isFinding)
    }

    /**
     * CTS requires only that noAuthRequired appear in exactly one list, and the
     * probe's own key always sets it, so it is the one tag that must not be in
     * the hardware-only set.
     */
    @Test
    fun noAuthRequiredInTheSoftwareListIsNotAFinding() {
        val v = evaluate(
            hardware = listOf(1, 2, 3, 5, 10, 702, 704, 705, 706, 718, 719),
            software = listOf(503, 701, 709),
        )
        assertFalse(v.hardwareOnlyTagInSoftwareList)
        assertFalse(v.isFinding)
    }

    @Test
    fun aSoftwareOnlyTagInTheHardwareListIsAFinding() {
        val v = evaluate(hardware = conforming + listOf(701))
        assertTrue(v.softwareOnlyTagInHardwareList)
        assertTrue(v.isFinding)
    }

    @Test
    fun theAttestationIdBlockIsExemptFromTheOrderReadout() {
        // Descending only across the ID tags, which is the measured genuine shape.
        assertFalse(RecordShape.isOutOfOrder(listOf(706, 717, 716, 712, 711, 710, 718, 719)))
        // Descending outside that block is still reported.
        assertTrue(RecordShape.isOutOfOrder(listOf(706, 705)))
    }

    // ---- gates -------------------------------------------------------------

    @Test
    fun anUnreadableListIsNotEvaluated() {
        val v = RecordShape.evaluate(null, listOf(701), 300, true, true, true)
        assertFalse(v.evaluated)
        assertFalse(v.isFinding)
        assertTrue(row(v).notApplicable)
        assertFalse(row(v).inconclusive)
    }

    @Test
    fun anUnanchoredOrSoftwareRecordIsNotEvaluated() {
        assertFalse(
            RecordShape.evaluate(conforming, emptyList(), 300, true, false, true).evaluated
        )
        assertFalse(
            RecordShape.evaluate(conforming, emptyList(), 300, false, true, true).evaluated
        )
    }

    /** An empty pinned set makes anchoring vacuous, so nothing here may speak. */
    @Test
    fun anEmptyPinnedSetIsNotEvaluated() {
        val v = RecordShape.evaluate(
            conforming + listOf(700), emptyList(), 300, true, true, false
        )
        assertFalse(v.evaluated)
        assertFalse(v.isFinding)
    }

    @Test
    fun preKeymaster4RecordsAreNotEvaluated() {
        assertFalse(
            RecordShape.evaluate(conforming + listOf(700), emptyList(), 2, true, true, true)
                .evaluated
        )
        assertFalse(
            RecordShape.evaluate(conforming + listOf(700), emptyList(), null, true, true, true)
                .evaluated
        )
        assertTrue(
            RecordShape.evaluate(conforming + listOf(700), emptyList(), 3, true, true, true)
                .evaluated
        )
    }

    // ---- the tag decoder ---------------------------------------------------

    @Test
    fun contextConstructedTagsRoundTrip() {
        for (n in listOf(1, 3, 10, 30, 31, 200, 503, 706, 719, 724)) {
            val encoded = AttestationAnalysis.contextConstructedTag(n)
            assertEquals(
                "tag $n must round trip",
                n,
                AttestationAnalysis.decodeContextConstructedTag(encoded)
            )
        }
    }

    /** A non-minimal encoding is hand-built, so it does not decode. */
    @Test
    fun nonMinimalTagEncodingsAreRejected() {
        // High form used for a number the low form can carry.
        assertEquals(
            null,
            AttestationAnalysis.decodeContextConstructedTag(byteArrayOf(0xBF.toByte(), 0x03))
        )
        // Leading continuation byte of zero.
        assertEquals(
            null,
            AttestationAnalysis.decodeContextConstructedTag(
                byteArrayOf(0xBF.toByte(), 0x80.toByte(), 0x03)
            )
        )
        // Not context-specific constructed.
        assertEquals(null, AttestationAnalysis.decodeContextConstructedTag(byteArrayOf(0x30)))
        assertEquals(null, AttestationAnalysis.decodeContextConstructedTag(ByteArray(0)))
    }

    // ---- helpers -----------------------------------------------------------

    private fun evaluate(
        hardware: List<Int> = conforming,
        software: List<Int> = listOf(701, 709),
    ) = RecordShape.evaluate(
        hardwareTags = hardware,
        softwareTags = software,
        attestationVersion = 300,
        hardwareBacked = true,
        anchored = true,
        haveTrustAnchors = true,
    )

    private fun row(v: RecordShape.Verdict) =
        DetectionResult.fromBitmask(
            if (v.isFinding) DetectionResult.DETECTION_ATTEST_SHAPE else 0,
            null, null, null, null, v,
        ).single { it.flag == DetectionResult.DETECTION_ATTEST_SHAPE }
}
