package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Shape and source checks on the day-precision patch levels.
 *
 * Tags 718 and 719 are specified as YYYYMMDD, and a value that is present but
 * is not a real date did not come from a conforming implementation. The
 * normalizers are deliberately asymmetric: the attested side accepts any valid
 * date, while the property side mirrors AOSP's own regex exactly, because a
 * parser more permissive than the HAL's would compare a value we invented
 * against a value the HAL never had.
 */
class AttestationPatchShapeTest {

    private val akitaDigest = "882588576475aeccb392982fe2fbc5f62c69c9fc84ba73e6c53cc052a1161586"

    @Test
    fun validDatesNormalize() {
        assertEquals(20241205, AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20241205L))
        assertEquals(20240805, AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20240805L))
        assertEquals(20080101, AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20080101L))
        assertEquals(20991231, AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20991231L))
    }

    @Test
    fun impossibleDatesDoNotNormalize() {
        // Day 00: what a month-granularity config value becomes when it is
        // multiplied out to the long form.
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20241100L))
        // Six digits in an eight-digit tag.
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(202412L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(202404L))
        // The AOSP nonsecure HAL's unwrap_or sentinel.
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(19700919L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20241232L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20241305L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(20071231L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(0L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonthDay(null))
    }

    @Test
    fun propertyParserMirrorsTheHalRegexExactly() {
        assertEquals(
            20241205,
            AttestationAnalysis.normalizePropertyPatchToYearMonthDay("2024-12-05")
        )
        // Every one of these is a value the HAL itself would have parsed as 0.
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay("20241205"))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay("2024-12"))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay(" 2024-12-05"))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay("2024-12-05\n"))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay("2024-13-05"))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay("2024-12-00"))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay(""))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonthDay(null))
    }

    /**
     * The finding is exactly one shape: a real year, a real month, day 00. That
     * is the form a month-granular config value takes when it is multiplied out
     * to the long form, and AOSP's own parser cannot produce it.
     */
    @Test
    fun onlyTheDayZeroShapeIsAFinding() {
        assertTrue(AttestationAnalysis.dayPrecisionPatchIsImpossible(20241100L))
        assertTrue(AttestationAnalysis.dayPrecisionPatchIsImpossible(20250400L))

        assertFalse(AttestationAnalysis.dayPrecisionPatchIsImpossible(0L))
        assertFalse(AttestationAnalysis.dayPrecisionPatchIsImpossible(null))
        assertFalse(AttestationAnalysis.dayPrecisionPatchIsImpossible(20240805L))
    }

    /**
     * Everything else that is not a date is forgiven and reported: a padded
     * year, a sentinel, an impossible day or month. No measurement was
     * available to show which coarse forms genuine vendors emit.
     */
    @Test
    fun otherNonDateShapesAreForgiven() {
        for (raw in listOf(20250000L, 19700919L, 20241232L, 20241305L, 202404L, 202412L)) {
            assertFalse("$raw must not be a finding",
                AttestationAnalysis.dayPrecisionPatchIsImpossible(raw))
            assertTrue("$raw must be reported",
                AttestationAnalysis.dayPrecisionPatchIsMonthOnly(raw))
        }
    }

    /**
     * An OEM that tracks the vendor or boot partition at month granularity is
     * non-conforming, not a spoofer, so a bare YYYYMM is separated out and
     * never reaches the verdict.
     */
    @Test
    fun theTwoBucketsAreDisjointAndCoverEverything() {
        for (raw in listOf(202404L, 202413L, 20241100L, 20250000L, 19700919L, 20241232L)) {
            val finding = AttestationAnalysis.dayPrecisionPatchIsImpossible(raw)
            val reported = AttestationAnalysis.dayPrecisionPatchIsMonthOnly(raw)
            assertTrue("$raw must land in exactly one bucket", finding != reported)
        }
        // A valid date lands in neither.
        assertFalse(AttestationAnalysis.dayPrecisionPatchIsImpossible(20240805L))
        assertFalse(AttestationAnalysis.dayPrecisionPatchIsMonthOnly(20240805L))
        assertFalse(AttestationAnalysis.dayPrecisionPatchIsMonthOnly(0L))
        assertFalse(AttestationAnalysis.dayPrecisionPatchIsMonthOnly(null))
    }

    @Test
    fun disagreementIsSymmetricWhereAheadOnlyIsNot() {
        assertFalse(AttestationAnalysis.patchLevelsDisagree(202412, 202412))
        assertTrue(AttestationAnalysis.patchLevelsDisagree(202412, 202408))
        // The older direction, which the ahead-only form cannot see.
        assertTrue(AttestationAnalysis.patchLevelsDisagree(202408, 202412))
        assertFalse(AttestationAnalysis.attestedPatchIsAheadOfProperty(202408, 202412))
        assertFalse(AttestationAnalysis.patchLevelsDisagree(null, 202412))
        assertFalse(AttestationAnalysis.patchLevelsDisagree(202412, null))
    }

    @Test
    fun attestationVersionIsReadFromKeyDescription() {
        assertEquals(300, AttestationAnalysis.parseAttestationVersion(realAkitaExtension()))
        assertNull(AttestationAnalysis.parseAttestationVersion(ByteArray(64) { 0x41 }))
    }

    @Test
    fun bootPatchLevelIsNowReadInProduction() {
        assertEquals(
            20240805L,
            AttestationAnalysis.parseHardwareEnforcedInteger(
                realAkitaExtension(), AttestationAnalysis.TAG_BOOT_PATCH_LEVEL
            )
        )
    }

    // ---- A3: the older direction, only behind the locked-and-verified gate --

    @Test
    fun olderAttestedOsPatchIsSuppressedWithoutTheGate() {
        val v = AttestationAnalysis.crossSourceMismatch(
            realAkitaExtension(),
            AttestationAnalysis.DeviceFacts("2024-12-05", "2024-08-05", akitaDigest, "sha256"),
            strictPatchEquality = false,
        )
        assertFalse(v.osPatchDisagrees)
        assertFalse(v.anyMismatch)
    }

    @Test
    fun olderAttestedOsPatchFiresWithTheGate() {
        val v = AttestationAnalysis.crossSourceMismatch(
            realAkitaExtension(),
            AttestationAnalysis.DeviceFacts("2024-12-05", "2024-08-05", akitaDigest, "sha256"),
            strictPatchEquality = true,
        )
        assertTrue(v.osPatchDisagrees)
        assertTrue(v.anyMismatch)
    }

    /**
     * On Keymaster 2 and 3 the TA receives os_patchlevel from the bootloader via
     * SetBootParams, not from the HAL's Configure() call, so a boot image left
     * behind the system partition makes a genuine, locked, green device read as
     * behind. Those devices are inside minSdk 24 and anchor to the same pinned
     * root, so the locked-and-verified gate alone does not exclude them.
     */
    @Test
    fun olderDirectionIsSuppressedOnPreKeymaster4Records() {
        val ext = extensionWith(osPatch = 202408L, attestationVersion = 2)
        val v = AttestationAnalysis.crossSourceMismatch(
            ext,
            AttestationAnalysis.DeviceFacts("2024-12-05", null, null, null),
            strictPatchEquality = true,
        )
        assertFalse(v.osPatchDisagrees)
        assertFalse(v.anyMismatch)
    }

    @Test
    fun olderDirectionFiresOnKeymaster4AndLater() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(osPatch = 202408L, attestationVersion = 3),
            AttestationAnalysis.DeviceFacts("2024-12-05", null, null, null),
            strictPatchEquality = true,
        )
        assertTrue(v.osPatchDisagrees)
        assertTrue(v.anyMismatch)
    }

    /** The newer direction is CTS-forbidden in every configuration, so it is ungated. */
    @Test
    fun newerDirectionFiresEvenOnPreKeymaster4Records() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(osPatch = 202412L, attestationVersion = 2),
            AttestationAnalysis.DeviceFacts("2024-08-05", null, null, null),
        )
        assertTrue(v.osPatchAhead)
        assertTrue(v.anyMismatch)
    }

    /** A closed gate must read as not observable, never as a pass. */
    @Test
    fun notEvaluatedIsNotAPass() {
        val v = AttestationAnalysis.CrossSourceVerdict.NOT_EVALUATED
        assertFalse(v.evaluated)
        assertFalse(v.anyMismatch)
        val row = DetectionResult.fromBitmask(0, null, v)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_CROSS_SOURCE }
        assertFalse(row.detected)
        assertTrue("a closed gate is unobservable, not a pass", row.notApplicable)
        assertFalse("and must not read as needing review", row.inconclusive)
    }

    @Test
    fun equalOsPatchIsSilentEvenWithTheGate() {
        val v = AttestationAnalysis.crossSourceMismatch(
            realAkitaExtension(),
            AttestationAnalysis.DeviceFacts("2024-08-05", "2024-08-05", akitaDigest, "sha256"),
            strictPatchEquality = true,
        )
        assertFalse(v.osPatchDisagrees)
        assertFalse(v.anyMismatch)
    }

    // ---- A4: the vendor level copied from the system property --------------

    /**
     * ro.vendor.build.security_patch is vendor_security_patch_level_prop, which
     * sepolicy grants to vendor_init, keystore and shell only. An app cannot
     * read it, so the vendor arms are computed for the readout and must never
     * reach the verdict: a finding may not depend on a privileged-only value.
     */
    @Test
    fun vendorArmsAreReportedButNeverFlag() {
        val ext = extensionWith(vendorPatch = 20241205L)
        val v = AttestationAnalysis.crossSourceMismatch(
            ext,
            AttestationAnalysis.DeviceFacts("2024-12-05", "2024-11-01", null, null),
        )
        assertTrue(v.vendorPatchCopiedFromSystemProperty)
        assertFalse(v.anyMismatch)

        val ahead = AttestationAnalysis.crossSourceMismatch(
            extensionWith(vendorPatch = 20241205L),
            AttestationAnalysis.DeviceFacts(null, "2024-11-01", null, null),
        )
        assertTrue(ahead.vendorPatchAhead)
        assertFalse(ahead.anyMismatch)
    }

    /** The shape of the one genuine test device: both properties are the same date. */
    @Test
    fun vendorCopyArmIsUnfireableWhenBothPropertiesAgree() {
        val ext = extensionWith(vendorPatch = 20241205L)
        val v = AttestationAnalysis.crossSourceMismatch(
            ext,
            AttestationAnalysis.DeviceFacts("2024-12-05", "2024-12-05", null, null),
        )
        assertFalse(v.vendorPatchCopiedFromSystemProperty)
        assertFalse(v.anyMismatch)
    }

    @Test
    fun correctVendorLevelIsSilent() {
        val ext = extensionWith(vendorPatch = 20241101L)
        val v = AttestationAnalysis.crossSourceMismatch(
            ext,
            AttestationAnalysis.DeviceFacts("2024-12-05", "2024-11-01", null, null),
        )
        assertFalse(v.vendorPatchCopiedFromSystemProperty)
    }

    @Test
    fun nonCanonicalVendorPropertyIsNoEvidence() {
        val ext = extensionWith(vendorPatch = 20241205L)
        val v = AttestationAnalysis.crossSourceMismatch(
            ext,
            AttestationAnalysis.DeviceFacts("2024-12-05", "2024-11", null, null),
        )
        assertFalse(v.vendorPatchCopiedFromSystemProperty)
    }

    // ---- A5: a day-precision level that is not a date ----------------------

    @Test
    fun malformedBootPatchLevelFires() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(bootPatch = 20241100L), AttestationAnalysis.DeviceFacts.EMPTY
        )
        assertTrue(v.malformedDayPrecisionPatchLevel)
        assertTrue(v.anyMismatch)
    }

    @Test
    fun sixDigitVendorPatchLevelIsReportedNotFlagged() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(vendorPatch = 202404L), AttestationAnalysis.DeviceFacts.EMPTY
        )
        assertFalse(v.malformedDayPrecisionPatchLevel)
        assertTrue(v.monthPrecisionDayLevel)
        assertFalse(v.anyMismatch)
    }

    @Test
    fun theRealRecordHasNoMalformedLevel() {
        val v = AttestationAnalysis.crossSourceMismatch(
            realAkitaExtension(), AttestationAnalysis.DeviceFacts.EMPTY
        )
        assertFalse(v.malformedDayPrecisionPatchLevel)
        assertFalse(v.anyMismatch)
    }

    @Test
    fun zeroPatchLevelIsSilent() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(bootPatch = 0L), AttestationAnalysis.DeviceFacts.EMPTY
        )
        assertFalse(v.malformedDayPrecisionPatchLevel)
    }

    // ---- A6: reported, deliberately not a detection ------------------------

    /**
     * VTS requires tag 719 by default, but --skip_boot_pl_check exists and no
     * test target available to this project can validate the arm positively, so
     * it is reported and does not drive the verdict. This test locks that in: if
     * someone promotes the arm, they have to change this test and say why.
     */
    @Test
    fun missingBootPatchLevelIsReportedButDoesNotFlag() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(vendorPatch = 20240805L, attestationVersion = 300),
            AttestationAnalysis.DeviceFacts.EMPTY,
        )
        assertTrue(v.bootPatchLevelMissing)
        assertFalse(v.anyMismatch)
    }

    @Test
    fun presentBootPatchLevelIsNotReportedMissing() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(vendorPatch = 20240805L, bootPatch = 20240805L, attestationVersion = 300),
            AttestationAnalysis.DeviceFacts.EMPTY,
        )
        assertFalse(v.bootPatchLevelMissing)
    }

    @Test
    fun preKeyMint3RecordIsNotReportedMissing() {
        val v = AttestationAnalysis.crossSourceMismatch(
            extensionWith(vendorPatch = 20240805L, attestationVersion = 3),
            AttestationAnalysis.DeviceFacts.EMPTY,
        )
        assertFalse(v.bootPatchLevelMissing)
    }

    @Test
    fun attestedValuesAreCarriedForTheReadout() {
        val v = AttestationAnalysis.crossSourceMismatch(
            realAkitaExtension(), AttestationAnalysis.DeviceFacts.EMPTY
        )
        assertEquals(20240805L, v.attestedBootPatchLevel)
        assertEquals(20240805L, v.attestedVendorPatchLevel)
    }

    // ---- helpers -----------------------------------------------------------

    /** A KeyDescription with the eight members KeyMint emits. */
    private fun extensionWith(
        vendorPatch: Long? = null,
        bootPatch: Long? = null,
        osPatch: Long? = null,
        attestationVersion: Int = 3,
    ): ByteArray {
        var entries = ByteArray(0)
        if (osPatch != null) {
            entries += tlv(hwTag(706), tlv(0x02, derInteger(osPatch)))
        }
        if (vendorPatch != null) {
            entries += tlv(hwTag(718), tlv(0x02, derInteger(vendorPatch)))
        }
        if (bootPatch != null) {
            entries += tlv(hwTag(719), tlv(0x02, derInteger(bootPatch)))
        }
        val keyDescription = tlv(
            0x30,
            tlv(0x02, derInteger(attestationVersion.toLong())) + tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x02, byteArrayOf(0x04)) + tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x04, byteArrayOf(0x01, 0x02)) + tlv(0x04, ByteArray(0)) +
                tlv(0x30, ByteArray(0)) + tlv(0x30, entries)
        )
        return tlv(0x04, keyDescription)
    }

    /** Context-specific constructed tag in the high-tag-number form. */
    private fun hwTag(tagNo: Int): ByteArray {
        val out = ArrayList<Byte>()
        var v = tagNo
        val base128 = ArrayList<Int>()
        while (v > 0) {
            base128.add(0, v and 0x7F)
            v = v shr 7
        }
        out.add(0xBF.toByte())
        for (i in base128.indices) {
            val last = i == base128.size - 1
            out.add((base128[i] or if (last) 0x00 else 0x80).toByte())
        }
        return out.toByteArray()
    }

    private fun derInteger(v: Long): ByteArray {
        if (v == 0L) return byteArrayOf(0)
        val bytes = ArrayList<Byte>()
        var x = v
        while (x > 0) {
            bytes.add(0, (x and 0xFF).toByte())
            x = x shr 8
        }
        // DER integers are signed, so a leading high bit needs a zero pad.
        if ((bytes[0].toInt() and 0x80) != 0) bytes.add(0, 0)
        return bytes.toByteArray()
    }

    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        tlv(byteArrayOf(tag.toByte()), content)

    private fun tlv(tag: ByteArray, content: ByteArray): ByteArray =
        tag + derLength(content.size) + content

    private fun derLength(n: Int): ByteArray {
        if (n < 0x80) return byteArrayOf(n.toByte())
        val bytes = ArrayList<Byte>()
        var v = n
        while (v > 0) {
            bytes.add(0, (v and 0xFF).toByte())
            v = v shr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    /** The same real KeyMint 3 record the cross-source suite uses. */
    private fun realAkitaExtension(): ByteArray {
        val keyDescription = hex(
            "3082013E0202012C0A01010202012C0A010104096368616C6C656E67650400308183" +
                "BF853D08020601923075E492BF8545730471306F314930470442636F6D2E676F6F" +
                "676C652E776972656C6573732E616E64726F69642E73656375726974792E617474" +
                "6573746174696F6E76657269666965722E636F6C6C6563746F7202010031220420" +
                "103938EE4537E59E8EE792F654504FB8346FC6B346D0BBC4415FC339FCFC8EC130" +
                "819AA1053103020102A203020103A30402020100AA03020101BF8377020500BF85" +
                "3E03020100BF85404C304A04200000000000000000000000000000000000000000" +
                "0000000000000000000000000101000A01020420882588576475AECCB392982FE2" +
                "FBC5F62C69C9FC84BA73E6C53CC052A1161586BF85410502030222E0BF85420502" +
                "030316A8BF854E0602040134D9A5BF854F0602040134D9A5"
        )
        return tlv(0x04, keyDescription)
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) {
            ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte()
        }
}
