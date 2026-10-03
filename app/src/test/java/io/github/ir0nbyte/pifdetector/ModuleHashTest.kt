package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A module-hash mismatch is ambiguous by construction: the TA pins the value
 * for its session, so a userspace reboot that applies a staged mainline update
 * leaves the platform ahead of the record on a genuine, locked device. Nothing
 * in this check may set a bit.
 */
class ModuleHashTest {

    private val blob = "a plausible DER module blob".toByteArray()
    private val correct = ModuleHash.sha256(blob)!!

    @Test
    fun theDigestOfThePlatformBlobMatches() {
        val s = evaluate(attested = correct)
        assertEquals(ModuleHash.Outcome.MATCHED, s.outcome)
        val row = row(s)
        assertFalse(row.detected)
        assertFalse(row.warning)
        assertFalse(row.inconclusive)
    }

    @Test
    fun aMismatchIsAWarningAndNeverADetection() {
        val s = evaluate(attested = ByteArray(32) { 0x11 })
        assertEquals(ModuleHash.Outcome.MISMATCHED, s.outcome)

        val row = row(s)
        assertFalse("a staged module update produces the same difference", row.detected)
        assertTrue(row.warning)
        assertTrue(row.detail!!.contains("userspace reboot"))
    }

    /** Nothing in the whole check can set the bit, whatever the outcome. */
    @Test
    fun noOutcomeEverSetsTheBit() {
        for (outcome in ModuleHash.Outcome.values()) {
            val row = row(ModuleHash.Status(outcome, 400))
            assertFalse("outcome $outcome must not detect", row.detected)
        }
    }

    /** The tag is OPTIONAL, so a record without it is permitted. */
    @Test
    fun anAbsentTagIsPermittedAndMustNotTurnTheCardAmber() {
        val s = evaluate(attested = null)
        assertEquals(ModuleHash.Outcome.ABSENT, s.outcome)
        val row = row(s)
        assertTrue("the tag is optional, so absence is unobservable", row.notApplicable)
        assertFalse(row.inconclusive)
        assertFalse(row.warning)
        assertTrue(row.detail!!.contains("optional"))
    }

    /**
     * Any present-but-not-32-byte value is an encoding this code does not know.
     * Comparing it against a SHA-256 would mismatch unconditionally.
     */
    @Test
    fun aWrongLengthHashIsMalformedNotMismatched() {
        for (size in listOf(1, 31, 33, 64)) {
            val s = evaluate(attested = ByteArray(size))
            assertEquals(
                "a $size-byte hash must not be compared",
                ModuleHash.Outcome.MALFORMED,
                s.outcome
            )
            assertFalse(row(s).detected)
        }
    }

    @Test
    fun preKeyMint4RecordsAreNotApplicable() {
        assertEquals(
            ModuleHash.Outcome.NOT_APPLICABLE,
            evaluate(attested = correct, keyMintVersion = 300).outcome
        )
        assertEquals(
            ModuleHash.Outcome.NOT_APPLICABLE,
            evaluate(attested = correct, keyMintVersion = null).outcome
        )
    }

    /** A platform with no module-hash API has nothing to compare against. */
    @Test
    fun noPlatformBlobIsNotApplicable() {
        assertEquals(
            ModuleHash.Outcome.NOT_APPLICABLE,
            evaluate(attested = correct, platform = null).outcome
        )
        assertEquals(
            ModuleHash.Outcome.NOT_APPLICABLE,
            evaluate(attested = correct, platform = ByteArray(0)).outcome
        )
    }

    @Test
    fun aSoftwareOrUnanchoredChainIsNotApplicable() {
        assertEquals(
            ModuleHash.Outcome.NOT_APPLICABLE,
            ModuleHash.evaluate(correct, blob, 400, hardwareBacked = false, anchored = true).outcome
        )
        assertEquals(
            ModuleHash.Outcome.NOT_APPLICABLE,
            ModuleHash.evaluate(correct, blob, 400, hardwareBacked = true, anchored = false).outcome
        )
    }

    /**
     * The Pixel 7a is SDK 35 and KeyMint 3, so this row cannot speak there and
     * must read inconclusive rather than as a pass.
     */
    @Test
    fun thePixelIsUnobservableAndMustNotTurnTheCardAmber() {
        val s = evaluate(attested = null, keyMintVersion = 300, platform = null)
        assertEquals(ModuleHash.Outcome.NOT_APPLICABLE, s.outcome)
        val row = row(s)
        assertFalse(row.detected)
        assertTrue("SDK 35 cannot supply a module hash at all", row.notApplicable)
        assertFalse("so a clean Pixel must still read as a pass", row.inconclusive)
    }

    private fun evaluate(
        attested: ByteArray?,
        platform: ByteArray? = blob,
        keyMintVersion: Int? = 400,
    ) = ModuleHash.evaluate(
        attestedModuleHash = attested,
        platformModuleInfo = platform,
        keyMintVersion = keyMintVersion,
        hardwareBacked = true,
        anchored = true,
    )

    private fun row(s: ModuleHash.Status) =
        DetectionResult.fromBitmask(0, null, null, null, null, null, s)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_MODULE_HASH }
}
