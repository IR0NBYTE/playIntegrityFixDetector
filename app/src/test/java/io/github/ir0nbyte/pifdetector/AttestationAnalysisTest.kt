package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class AttestationAnalysisTest {
    @Test
    fun chainTooShortIsNotBroken() {
        assertFalse(AttestationAnalysis.chainIsCryptographicallyBroken(0) { true })
        assertFalse(AttestationAnalysis.chainIsCryptographicallyBroken(1) { false })
    }

    @Test
    fun fullyValidChainIsNotBroken() {
        assertFalse(AttestationAnalysis.chainIsCryptographicallyBroken(3) { true })
    }

    @Test
    fun anyBrokenLinkBreaksChain() {
        assertTrue(AttestationAnalysis.chainIsCryptographicallyBroken(3) { i -> i != 0 })
        assertTrue(AttestationAnalysis.chainIsCryptographicallyBroken(2) { false })
    }

    @Test
    fun nullRootOfTrustNeverContradicts() {
        assertFalse(AttestationAnalysis.isBootContradiction(null, deviceTampered = true))
    }

    @Test
    fun cleanDeviceNeverContradicts() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = true, verifiedBootState = 0)
        assertFalse(AttestationAnalysis.isBootContradiction(rot, deviceTampered = false))
    }

    @Test
    fun lockedAttestationOnTamperedDeviceContradicts() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = true, verifiedBootState = 2)
        assertTrue(AttestationAnalysis.isBootContradiction(rot, deviceTampered = true))
    }

    @Test
    fun verifiedBootStateOnTamperedDeviceContradicts() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = false, verifiedBootState = 0)
        assertTrue(AttestationAnalysis.isBootContradiction(rot, deviceTampered = true))
    }

    @Test
    fun honestUnlockedAttestationDoesNotContradict() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = false, verifiedBootState = 2)
        assertFalse(AttestationAnalysis.isBootContradiction(rot, deviceTampered = true))
    }

    @Test
    fun parsesDeviceLockedAndVerifiedState() {
        val ext = buildExtension(deviceLocked = true, verifiedBootState = 0)
        val rot = AttestationAnalysis.parseRootOfTrust(ext)
        assertEquals(AttestationAnalysis.RootOfTrust(true, 0), rot)
    }

    @Test
    fun parsesUnlockedAndUnverifiedState() {
        val ext = buildExtension(deviceLocked = false, verifiedBootState = 2)
        val rot = AttestationAnalysis.parseRootOfTrust(ext)
        assertEquals(AttestationAnalysis.RootOfTrust(false, 2), rot)
    }

    @Test
    fun returnsNullOnGarbage() {
        assertNull(AttestationAnalysis.parseRootOfTrust(byteArrayOf(0x01, 0x02, 0x03)))
        assertNull(AttestationAnalysis.parseRootOfTrust(ByteArray(0)))
    }

    @Test
    fun returnsNullWhenNoRootOfTrustTag() {
        val keyDesc = tlv(0x30, tlv(0x02, byteArrayOf(0x01)))
        val ext = tlv(0x04, keyDesc)
        assertNull(AttestationAnalysis.parseRootOfTrust(ext))
    }

    @Test
    fun propertiesClaimingLockedAgainstUnlockedAttestationIsASpoof() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = false, verifiedBootState = 2)
        assertTrue(
            AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked = true)
        )
    }

    @Test
    fun lockedButUnverifiedAttestationStillContradictsLockedProperties() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = true, verifiedBootState = 2)
        assertTrue(
            AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked = true)
        )
    }

    @Test
    fun genuinelyLockedDeviceDoesNotContradict() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = true, verifiedBootState = 0)
        assertFalse(
            AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked = true)
        )
    }

    @Test
    fun honestlyUnlockedDeviceDoesNotContradict() {
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = false, verifiedBootState = 2)
        assertFalse(
            AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked = false)
        )
    }

    @Test
    fun nullRootOfTrustNeverContradictsProperties() {
        assertFalse(
            AttestationAnalysis.bootPropertiesContradictAttestation(null, propertiesClaimLocked = true)
        )
    }

    @Test
    fun matchingChallengeIsNotMismatch() {
        val n = byteArrayOf(1, 2, 3, 4)
        assertFalse(AttestationAnalysis.challengeMismatch(n.copyOf(), n))
    }

    @Test
    fun differingChallengeIsMismatch() {
        assertTrue(
            AttestationAnalysis.challengeMismatch(byteArrayOf(9, 9), byteArrayOf(1, 2, 3, 4))
        )
    }

    @Test
    fun nullChallengeNeverMismatches() {
        assertFalse(AttestationAnalysis.challengeMismatch(null, byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun parsesAttestationChallengeAtIndexFour() {
        val nonce = byteArrayOf(0x11, 0x22, 0x33, 0x44)
        val ext = buildExtensionWithChallenge(nonce)
        assertTrue(AttestationAnalysis.parseAttestationChallenge(ext)!!.contentEquals(nonce))
    }

    @Test
    fun parseChallengeReturnsNullOnGarbage() {
        assertNull(AttestationAnalysis.parseAttestationChallenge(byteArrayOf(0x05, 0x00)))
    }

    @Test
    fun realPixelChainParsesAsTrustedEnvironmentNotSoftware() {
        val level = AttestationAnalysis.parseAttestationSecurityLevel(realAkitaExtension())
        assertEquals(TRUSTED_ENVIRONMENT, level)
        assertNotEquals(AttestationAnalysis.SECURITY_LEVEL_SOFTWARE, level)
    }

    @Test
    fun softwareBackedChainParsesAsSoftware() {
        assertEquals(
            AttestationAnalysis.SECURITY_LEVEL_SOFTWARE,
            AttestationAnalysis.parseAttestationSecurityLevel(
                buildExtensionWithSecurityLevel(AttestationAnalysis.SECURITY_LEVEL_SOFTWARE)
            )
        )
    }

    @Test
    fun strongBoxChainIsNotTreatedAsSoftware() {
        assertEquals(2, AttestationAnalysis.parseAttestationSecurityLevel(
            buildExtensionWithSecurityLevel(2)))
    }

    @Test
    fun unparseableSecurityLevelIsNullNotSoftware() {
        for (bad in listOf(byteArrayOf(0x01, 0x02, 0x03), ByteArray(0), byteArrayOf(0x05, 0x00))) {
            val level = AttestationAnalysis.parseAttestationSecurityLevel(bad)
            assertNull(level)
            assertNotEquals(AttestationAnalysis.SECURITY_LEVEL_SOFTWARE, level)
        }
    }

    private fun buildExtensionWithSecurityLevel(level: Int): ByteArray {
        val keyDescription = tlv(
            0x30,
            tlv(0x02, byteArrayOf(0x03)) +
                tlv(0x0A, byteArrayOf(level.toByte())) +
                tlv(0x02, byteArrayOf(0x04)) +
                tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x04, byteArrayOf(0x01, 0x02))
        )
        return tlv(0x04, keyDescription)
    }

    private companion object {
        const val TRUSTED_ENVIRONMENT = 1
    }

    @Test
    fun normalizeSerialIsLowercaseHexNoLeadingZeros() {
        assertEquals("ff", AttestationAnalysis.normalizeSerial(BigInteger.valueOf(255)))
        assertEquals(
            "1234567890abcdef",
            AttestationAnalysis.normalizeSerial(BigInteger("1234567890abcdef", 16))
        )
    }

    @Test
    fun decimalKeyedRevocationEntryIsFound() {
        val serial = BigInteger("6681152659205225093")
        val listedAsDecimal = setOf("6681152659205225093")

        assertTrue(
            AttestationAnalysis.anyCertRevoked(
                AttestationAnalysis.serialLookupKeys(serial), listedAsDecimal
            )
        )

        assertFalse(
            AttestationAnalysis.anyCertRevoked(
                listOf(AttestationAnalysis.normalizeSerial(serial)), listedAsDecimal
            )
        )
    }

    @Test
    fun hexKeyedRevocationEntryStillFound() {
        val serial = BigInteger("c35747a084470c3135aeefe2b8d40cd6", 16)
        assertTrue(
            AttestationAnalysis.anyCertRevoked(
                AttestationAnalysis.serialLookupKeys(serial),
                setOf("c35747a084470c3135aeefe2b8d40cd6")
            )
        )
    }

    @Test
    fun serialLookupKeysCoversBothEncodings() {
        val keys = AttestationAnalysis.serialLookupKeys(BigInteger("6681152659205225093"))
        assertTrue(keys.contains("6681152659205225093"))
        assertTrue(keys.contains("5cb838f1fe157a85"))

        assertEquals(1, AttestationAnalysis.serialLookupKeys(BigInteger.valueOf(7)).size)
    }

    @Test
    fun negativeSerialsNormalizeToUnsigned() {
        AttestationAnalysis.serialLookupKeys(BigInteger("-255")).forEach {
            assertFalse(it.startsWith("-"))
        }
    }

    @Test
    fun revokedSerialInChainFlags() {
        assertTrue(AttestationAnalysis.anyCertRevoked(listOf("ff", "ab"), setOf("ab")))
    }

    @Test
    fun cleanSerialsDoNotFlag() {
        assertFalse(AttestationAnalysis.anyCertRevoked(listOf("ff", "ab"), setOf("cc")))
        assertFalse(AttestationAnalysis.anyCertRevoked(listOf("ff", "ab"), emptySet()))
    }

    @Test
    fun chainEndingInPinnedRootAnchors() {
        val roots = AttestationRoots.pinnedRoots

        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[0]), roots))
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[1]), roots))
    }

    @Test
    fun chainNotAnchoredWhenNoPinnedRootMatches() {
        val roots = AttestationRoots.pinnedRoots

        assertFalse(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[0]), listOf(roots[1])))
    }

    @Test
    fun anchorCheckFailsSafeOnEmptyInputs() {
        val roots = AttestationRoots.pinnedRoots

        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(emptyList(), roots))
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[0]), emptyList()))
    }

    @Test
    fun parsesRealKeymasterRootOfTrustLayout() {
        val rot = byteArrayOf(0x04, 0x00) +
            byteArrayOf(0x01, 0x01, 0x00) +
            byteArrayOf(0x0A, 0x01, 0x02) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(false, 2), parsed)
    }

    @Test
    fun parsesRealKeyMintRootOfTrustLayout() {
        val rot = byteArrayOf(0x04, 0x20) + ByteArray(32) +
            byteArrayOf(0x01, 0x01, 0x00) +
            byteArrayOf(0x0A, 0x01, 0x02) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(false, 2), parsed)
    }

    @Test
    fun detectsForgedLockedVerifiedRootOfTrust() {
        val rot = byteArrayOf(0x04, 0x20) + ByteArray(32) +
            byteArrayOf(0x01, 0x01, 0x01) +
            byteArrayOf(0x0A, 0x01, 0x00) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(true, 0), parsed)
        assertTrue(AttestationAnalysis.isBootContradiction(parsed, deviceTampered = true))
    }

    @Test
    fun parsesRealAkitaKeyDescriptionEndToEnd() {
        val ext = realAkitaExtension()

        assertTrue(
            AttestationAnalysis.parseAttestationChallenge(ext)!!
                .contentEquals("challenge".toByteArray(Charsets.US_ASCII))
        )

        assertEquals(
            AttestationAnalysis.RootOfTrust(false, 2),
            AttestationAnalysis.parseRootOfTrust(ext)
        )
    }

    @Test
    fun parsesRootOfTrustWithLongFormLengths() {
        val rot = byteArrayOf(0x04.toByte(), 0x81.toByte(), 0xC8.toByte()) + ByteArray(200) +
            byteArrayOf(0x01, 0x01, 0x01) +
            byteArrayOf(0x0A, 0x01, 0x00) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(true, 0), parsed)
    }

    @Test
    fun contextTagUsesHighTagNumberFormAboveThirty() {
        assertArrayEquals(
            byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40),
            AttestationAnalysis.contextConstructedTag(704)
        )
        assertArrayEquals(hwTag(503), AttestationAnalysis.contextConstructedTag(503))
        assertArrayEquals(hwTag(504), AttestationAnalysis.contextConstructedTag(504))
        assertArrayEquals(hwTag(505), AttestationAnalysis.contextConstructedTag(505))
    }

    @Test
    fun contextTagUsesShortFormBelowThirtyOne() {
        assertArrayEquals(byteArrayOf(0xA1.toByte()), AttestationAnalysis.contextConstructedTag(1))
        assertArrayEquals(byteArrayOf(0xAA.toByte()), AttestationAnalysis.contextConstructedTag(10))
    }

    @Test
    fun findsTagPresentInHardwareEnforcedList() {
        val ext = extensionWithHardwareTags(503)
        assertTrue(AttestationAnalysis.hasHardwareEnforcedTag(ext, 503))
        assertFalse(AttestationAnalysis.hasHardwareEnforcedTag(ext, 504))
    }

    @Test
    fun tagLookupFailsSafeOnGarbage() {
        assertFalse(AttestationAnalysis.hasHardwareEnforcedTag(ByteArray(0), 503))
        assertFalse(AttestationAnalysis.hasHardwareEnforcedTag(byteArrayOf(1, 2, 3), 503))
    }

    @Test
    fun noAuthRequiredAloneIsAContradiction() {
        assertTrue(AttestationAnalysis.authRequirementContradiction(extensionWithHardwareTags(503)))
    }

    @Test
    fun authTagsPresentClearsTheContradiction() {
        assertFalse(
            AttestationAnalysis.authRequirementContradiction(extensionWithHardwareTags(503, 504))
        )
        assertFalse(
            AttestationAnalysis.authRequirementContradiction(extensionWithHardwareTags(503, 505))
        )
    }

    @Test
    fun absentNoAuthTagIsNotAContradiction() {
        assertFalse(
            AttestationAnalysis.authRequirementContradiction(extensionWithHardwareTags(504, 505))
        )
        assertFalse(AttestationAnalysis.authRequirementContradiction(ByteArray(0)))
    }

    @Test
    fun leafSignedWithRequestedDigestIsAnomalous() {
        assertTrue(AttestationAnalysis.leafSignatureTracksRequestedDigest("SHA512withECDSA"))
        assertTrue(AttestationAnalysis.leafSignatureTracksRequestedDigest("sha512withecdsa"))
        assertTrue(AttestationAnalysis.leafSignatureTracksRequestedDigest("SHA-512withRSA"))
    }

    @Test
    fun otherNonSha256DigestsAreNotEvidence() {
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest("sha384withecdsa"))
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest("SHA1withRSA"))
    }

    @Test
    fun sha256LeafSignatureIsNormal() {
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest("SHA256withECDSA"))
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest("SHA256withRSA"))
    }

    @Test
    fun unknownSignatureAlgorithmFailsSafe() {
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest(null))
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest(""))
        assertFalse(AttestationAnalysis.leafSignatureTracksRequestedDigest("Ed25519"))
    }

    @Test
    fun multiCertAndEmptyChainsAreNotSelfSignedSingletons() {
        assertFalse(AttestationAnalysis.isSelfSignedSingleCert(emptyList()))
        val roots = AttestationRoots.pinnedRoots
        if (roots.size >= 2) {
            assertFalse(AttestationAnalysis.isSelfSignedSingleCert(roots))
        }
    }

    @Test
    fun selfSignedCertWithoutAttestationExtensionDoesNotFlag() {
        val root = AttestationRoots.pinnedRoots.firstOrNull() ?: return
        assertFalse(AttestationAnalysis.isSelfSignedSingleCert(listOf(root)))
    }

    @Test
    fun findsNoAuthRequiredTagInRealPixelExtension() {
        val ext = realAkitaExtension()
        assertTrue(AttestationAnalysis.hasHardwareEnforcedTag(ext, 503))
        assertFalse(AttestationAnalysis.hasHardwareEnforcedTag(ext, 504))
        assertFalse(AttestationAnalysis.hasHardwareEnforcedTag(ext, 505))
    }

    @Test
    fun findsOtherRealHardwareEnforcedTags() {
        val ext = realAkitaExtension()
        assertTrue(AttestationAnalysis.hasHardwareEnforcedTag(ext, 702))
        assertTrue(AttestationAnalysis.hasHardwareEnforcedTag(ext, 704))
        assertTrue(AttestationAnalysis.hasHardwareEnforcedTag(ext, 719))
    }

    @Test
    fun authContradictionPredicateAloneIsNotADetection() {
        assertTrue(AttestationAnalysis.authRequirementContradiction(realAkitaExtension()))
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
        return tlv(0x04, keyDescription)
    }

    private fun hwTag(tagNo: Int): ByteArray = when (tagNo) {
        503 -> byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x77)
        504 -> byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x78)
        505 -> byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x79)
        else -> throw IllegalArgumentException("no fixture for tag $tagNo")
    }

    private fun extensionWithHardwareTags(vararg tagNos: Int): ByteArray {
        var entries = ByteArray(0)
        for (t in tagNos) {
            entries += tlv(hwTag(t), tlv(0x05, ByteArray(0)))
        }
        val hardwareEnforced = tlv(0x30, entries)
        val keyDescription = tlv(0x30, tlv(0x02, byteArrayOf(0x03)) + hardwareEnforced)
        return tlv(0x04, keyDescription)
    }

    private fun buildExtensionWithChallenge(challenge: ByteArray): ByteArray {
        val keyDescription = tlv(
            0x30,
            tlv(0x02, byteArrayOf(0x03)) +
                tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x02, byteArrayOf(0x04)) +
                tlv(0x0A, byteArrayOf(0x01)) +
                tlv(0x04, challenge)
        )
        return tlv(0x04, keyDescription)
    }

    private fun buildExtension(deviceLocked: Boolean, verifiedBootState: Int): ByteArray {
        val rotSeqContent =
            tlv(0x04, byteArrayOf(0xAA.toByte(), 0xBB.toByte())) +
                tlv(0x01, byteArrayOf(if (deviceLocked) 0xFF.toByte() else 0x00)) +
                tlv(0x0A, byteArrayOf(verifiedBootState.toByte())) +
                tlv(0x04, byteArrayOf(0xCC.toByte(), 0xDD.toByte()))
        return extensionWithRootOfTrust(rotSeqContent)
    }

    private fun extensionWithRootOfTrust(rootOfTrustSeqContent: ByteArray): ByteArray {
        val rootOfTrustSeq = tlv(0x30, rootOfTrustSeqContent)
        val tagged704 = tlv(byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40), rootOfTrustSeq)
        val hardwareEnforced = tlv(0x30, tagged704)
        val keyDescription = tlv(0x30, tlv(0x02, byteArrayOf(0x03)) + hardwareEnforced)
        return tlv(0x04, keyDescription)
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

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
            v = v ushr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }
}
