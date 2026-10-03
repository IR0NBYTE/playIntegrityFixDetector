package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Asserts against a real KeyMint attestation record rather than synthetic bytes,
 * so the tag encodings are pinned to what hardware actually emits.
 */
class AttestationCrossSourceTest {

    private val realBootHashHex =
        "882588576475aeccb392982fe2fbc5f62c69c9fc84ba73e6c53cc052a1161586"

    @Test
    fun parsesOsPatchLevelAsYearMonth() {
        val raw = AttestationAnalysis.parseHardwareEnforcedInteger(
            realAkitaExtension(), AttestationAnalysis.TAG_OS_PATCH_LEVEL
        )
        assertEquals(202408L, raw)
        assertEquals(202408, AttestationAnalysis.normalizeAttestedPatchToYearMonth(raw))
    }

    @Test
    fun parsesVendorPatchLevelAsYearMonthDay() {
        val raw = AttestationAnalysis.parseHardwareEnforcedInteger(
            realAkitaExtension(), AttestationAnalysis.TAG_VENDOR_PATCH_LEVEL
        )
        assertEquals(20240805L, raw)
        assertEquals(202408, AttestationAnalysis.normalizeAttestedPatchToYearMonth(raw))
    }

    @Test
    fun parsesBootPatchLevel() {
        assertEquals(
            20240805L,
            AttestationAnalysis.parseHardwareEnforcedInteger(
                realAkitaExtension(), AttestationAnalysis.TAG_BOOT_PATCH_LEVEL
            )
        )
    }

    @Test
    fun absentTagReturnsNull() {
        assertNull(AttestationAnalysis.parseHardwareEnforcedInteger(realAkitaExtension(), 999))
    }

    @Test
    fun parsesVerifiedBootHashFromFourFieldRootOfTrust() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        assertNotNull(hash)
        assertEquals(32, hash!!.size)
        assertEquals(realBootHashHex, hash.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun garbageExtensionYieldsNullRatherThanThrowing() {
        val garbage = ByteArray(64) { 0x41 }
        assertNull(AttestationAnalysis.parseHardwareEnforcedInteger(garbage, 706))
        assertNull(AttestationAnalysis.parseVerifiedBootHash(garbage))
    }

    // Normalisation

    @Test
    fun propertyFormatsNormalizeIdentically() {
        assertEquals(202412, AttestationAnalysis.normalizePropertyPatchToYearMonth("2024-12-05"))
        assertEquals(202412, AttestationAnalysis.normalizePropertyPatchToYearMonth("20241205"))
        assertEquals(202412, AttestationAnalysis.normalizePropertyPatchToYearMonth("2024-12"))
        assertEquals(202412, AttestationAnalysis.normalizePropertyPatchToYearMonth("202412"))
    }

    @Test
    fun unparseablePatchValuesAreUnknown() {
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonth(null))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonth(""))
        assertNull(AttestationAnalysis.normalizePropertyPatchToYearMonth("not a date"))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonth(0L))
        assertNull(AttestationAnalysis.normalizeAttestedPatchToYearMonth(202413L))
    }

    // Direction

    @Test
    fun attestedNewerThanPropertyFlags() {
        assertTrue(AttestationAnalysis.attestedPatchIsAheadOfProperty(202412, 202408))
    }

    /** A vendor property lagging the attested level is legitimate and must not flag. */
    @Test
    fun attestedOlderThanPropertyDoesNotFlag() {
        assertFalse(AttestationAnalysis.attestedPatchIsAheadOfProperty(202408, 202412))
    }

    @Test
    fun equalPatchLevelsDoNotFlag() {
        assertFalse(AttestationAnalysis.attestedPatchIsAheadOfProperty(202412, 202412))
    }

    @Test
    fun unknownEitherSideDoesNotFlag() {
        assertFalse(AttestationAnalysis.attestedPatchIsAheadOfProperty(null, 202412))
        assertFalse(AttestationAnalysis.attestedPatchIsAheadOfProperty(202412, null))
    }

    // Verified boot hash

    @Test
    fun matchingBootHashDoesNotFlag() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        assertFalse(
            AttestationAnalysis.verifiedBootHashMismatch(hash, realBootHashHex, "sha256")
        )
    }

    @Test
    fun differingBootHashFlags() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        val other = "4a63b2f043ffe307a73af9575090f0863777a8498fc3cddf60b7e99a17303ed6"
        assertTrue(AttestationAnalysis.verifiedBootHashMismatch(hash, other, "sha256"))
    }

    @Test
    fun nonSha256HashAlgIsSkipped() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        val other = "4a63b2f043ffe307a73af9575090f0863777a8498fc3cddf60b7e99a17303ed6"
        assertFalse(AttestationAnalysis.verifiedBootHashMismatch(hash, other, "sha512"))
        assertFalse(AttestationAnalysis.verifiedBootHashMismatch(hash, other, null))
    }

    /**
     * An all-zero attested hash is what AOSP emits when it could not read
     * ro.boot.vbmeta.digest, for any reason. Treating it as a contradiction
     * overreached: no measurement shows a genuine device cannot produce it, so
     * it is reported and never called.
     */
    @Test
    fun allZeroAttestedHashIsReportedNotCalled() {
        assertFalse(
            AttestationAnalysis.verifiedBootHashMismatch(
                ByteArray(32), realBootHashHex, "sha256"
            )
        )
        assertTrue(
            AttestationAnalysis.attestedBootHashUnusable(ByteArray(32))
        )
    }

    /** An all-zero property means the DEVICE has no digest, which is no evidence. */
    @Test
    fun allZeroPropertyDigestIsSkipped() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        assertFalse(AttestationAnalysis.verifiedBootHashMismatch(hash, "0".repeat(64), "sha256"))
    }

    @Test
    fun anAttestedHashCarryingNoDigestIsReportedNotCalled() {
        // All zeroes on both sides.
        assertFalse(
            AttestationAnalysis.verifiedBootHashMismatch(
                ByteArray(32), "0".repeat(64), "sha256"
            )
        )
        // All zeroes against a perfectly good device digest. Still not called:
        // zeroes are what an implementation emits when it could not read the
        // device's own digest.
        assertFalse(
            AttestationAnalysis.verifiedBootHashMismatch(
                ByteArray(32), realBootHashHex, "sha256"
            )
        )
        assertTrue(AttestationAnalysis.attestedBootHashUnusable(ByteArray(32)))
        assertTrue(AttestationAnalysis.attestedBootHashUnusable(ByteArray(20)))
        assertFalse(AttestationAnalysis.attestedBootHashUnusable(null))

        val real = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        assertFalse(AttestationAnalysis.attestedBootHashUnusable(real))
    }

    /**
     * CTS asserts 32 bytes, but an unexpected length is an encoding this code
     * does not know rather than a contradiction, so it is reported.
     */
    @Test
    fun wrongLengthAttestedHashIsReportedNotCalled() {
        assertFalse(
            AttestationAnalysis.verifiedBootHashMismatch(
                ByteArray(20), realBootHashHex, "sha256"
            )
        )
        assertTrue(
            AttestationAnalysis.attestedBootHashUnusable(ByteArray(20))
        )
    }

    @Test
    fun absentAttestedHashIsNoEvidence() {
        assertFalse(
            AttestationAnalysis.verifiedBootHashMismatch(null, realBootHashHex, "sha256")
        )
    }

    @Test
    fun malformedDigestIsSkipped() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        assertFalse(AttestationAnalysis.verifiedBootHashMismatch(hash, "zz", "sha256"))
        assertFalse(AttestationAnalysis.verifiedBootHashMismatch(hash, null, "sha256"))
    }

    // Whole verdict

    @Test
    fun consistentDeviceProducesNoMismatch() {
        val facts = AttestationAnalysis.DeviceFacts(
            systemSecurityPatch = "2024-08-05",
            vendorSecurityPatch = "2024-08-05",
            vbmetaDigestHex = realBootHashHex,
            vbmetaHashAlg = "sha256",
        )
        val verdict = AttestationAnalysis.crossSourceMismatch(realAkitaExtension(), facts)
        assertFalse(verdict.anyMismatch)
    }

    @Test
    fun attestationAheadOfSystemPropertyIsAMismatch() {
        val facts = AttestationAnalysis.DeviceFacts(
            systemSecurityPatch = "2023-01-01",
            vendorSecurityPatch = "2024-08-05",
            vbmetaDigestHex = realBootHashHex,
            vbmetaHashAlg = "sha256",
        )
        val verdict = AttestationAnalysis.crossSourceMismatch(realAkitaExtension(), facts)
        assertTrue(verdict.osPatchAhead)
        assertTrue(verdict.anyMismatch)
    }

    @Test
    fun bootHashDisagreementIsAMismatch() {
        val hash = AttestationAnalysis.parseVerifiedBootHash(realAkitaExtension())
        val other = "4a63b2f043ffe307a73af9575090f0863777a8498fc3cddf60b7e99a17303ed6"
        // The pure comparison still reports the disagreement.
        assertTrue(AttestationAnalysis.verifiedBootHashMismatch(hash, other, "sha256"))
        // The verdict only carries it on a device whose own record says it is
        // locked and verified, which is where the VTS assertion applies.
        assertFalse(
            AttestationAnalysis.crossSourceMismatch(
                realAkitaExtension(),
                AttestationAnalysis.DeviceFacts("2024-08-05", null, other, "sha256"),
                strictPatchEquality = false,
            ).bootHashMismatch
        )
        assertTrue(
            AttestationAnalysis.crossSourceMismatch(
                realAkitaExtension(),
                AttestationAnalysis.DeviceFacts("2024-08-05", null, other, "sha256"),
                strictPatchEquality = true,
            ).bootHashMismatch
        )
    }

    /** No facts at all must never flag. */
    @Test
    fun emptyFactsProduceNoMismatch() {
        val verdict = AttestationAnalysis.crossSourceMismatch(
            realAkitaExtension(), AttestationAnalysis.DeviceFacts.EMPTY
        )
        assertFalse(verdict.anyMismatch)
    }

    // Regression tests for the DER-scoping attacks. The lookups must read the
    // real top-level authorization entry, not one an adversary can position
    // where a strict verifier would never look.

    /**
     * A decoy [706] buried inside an earlier constructed member must not shadow
     * the real top-level entry. Otherwise the detector reads one patch level
     * while Google's verifier reads another.
     */
    @Test
    fun nestedDecoyTagDoesNotShadowTheRealEntry() {
        val decoy = tlv(byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x42), tlv(0x02, hex("0316A8")))
        val purposeSetWithDecoy = tlv(byteArrayOf(0xA1.toByte()), tlv(0x02, byteArrayOf(0x02)) + decoy)
        val realOsPatch =
            tlv(byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x42), tlv(0x02, hex("033839")))
        val ext = extensionWithHardwareEnforced(purposeSetWithDecoy + realOsPatch)

        assertEquals(
            "must read the real top-level entry (211001), not the nested decoy (202408)",
            211001L,
            AttestationAnalysis.parseHardwareEnforcedInteger(
                ext, AttestationAnalysis.TAG_OS_PATCH_LEVEL
            )
        )
    }

    /** A duplicate at the top level is a hand-built record, so refuse to guess. */
    @Test
    fun duplicateTopLevelTagIsRejected() {
        val once = tlv(byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x42), tlv(0x02, hex("0316A8")))
        val ext = extensionWithHardwareEnforced(once + once)
        assertNull(
            AttestationAnalysis.parseHardwareEnforcedInteger(
                ext, AttestationAnalysis.TAG_OS_PATCH_LEVEL
            )
        )
    }

    /**
     * Appending a ninth member to KeyDescription must not redirect the lookup
     * into a list the adversary fully controls.
     */
    @Test
    fun appendedNinthKeyDescriptionChildIsRejected() {
        val attackerList = tlv(
            0x30,
            tlv(byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x42), tlv(0x02, hex("0316A8")))
        )
        val nineChildren = tlv(
            0x30,
            tlv(0x02, byteArrayOf(0x03)) + tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x02, byteArrayOf(0x04)) + tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x04, byteArrayOf(0x01, 0x02)) + tlv(0x04, ByteArray(0)) +
                tlv(0x30, ByteArray(0)) + tlv(0x30, ByteArray(0)) +
                attackerList
        )
        val ext = tlv(0x04, nineChildren)
        assertNull(
            AttestationAnalysis.parseHardwareEnforcedInteger(
                ext, AttestationAnalysis.TAG_OS_PATCH_LEVEL
            )
        )
        assertNull(AttestationAnalysis.parseVerifiedBootHash(ext))
    }

    private fun extensionWithHardwareEnforced(
        entries: ByteArray,
        attestationVersion: ByteArray = byteArrayOf(0x03),
    ): ByteArray {
        val keyDescription = tlv(
            0x30,
            tlv(0x02, attestationVersion) + tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x02, byteArrayOf(0x04)) + tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x04, byteArrayOf(0x01, 0x02)) + tlv(0x04, ByteArray(0)) +
                tlv(0x30, ByteArray(0)) + tlv(0x30, entries)
        )
        return tlv(0x04, keyDescription)
    }

    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        tlv(byteArrayOf(tag.toByte()), content)

    private fun tlv(tag: ByteArray, content: ByteArray): ByteArray =
        tag + derLength(content.size) + content

    private fun derLength(n: Int): ByteArray {
        if (n < 0x80) return byteArrayOf(n.toByte())
        val bytes = ArrayList<Byte>()
        var v = n
        while (v > 0) { bytes.add(0, (v and 0xFF).toByte()); v = v shr 8 }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

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
        return byteArrayOf(
            0x04, 0x82.toByte(),
            ((keyDescription.size shr 8) and 0xFF).toByte(),
            (keyDescription.size and 0xFF).toByte()
        ) + keyDescription
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
