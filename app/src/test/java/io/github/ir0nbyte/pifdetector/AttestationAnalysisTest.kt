package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/*
 * Unit tests for the pure decision/parsing logic behind KeyAttestationProbe.
 * The live AndroidKeyStore probe needs a real device and is NOT exercised here;
 * these cover the parts that determine whether a real attestation result is
 * treated as an anomaly. DER fixtures are hand-built below.
 *
 * NOTE: these fixtures encode the attestation schema as we understand it
 * (RootOfTrust under [704] EXPLICIT, deviceLocked at index 1, verifiedBootState
 * at index 2). They verify the parser/decision logic is internally correct and
 * regression-safe; they do NOT substitute for validating against a real
 * device's Keymaster/KeyMint output. The parser fails safe (returns null) on
 * anything unexpected, so a schema gap degrades to "no detection", never a
 * false positive.
 */
class AttestationAnalysisTest {

    // --- 1a: chain signature validation logic -------------------------------

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
        // link 0 valid, link 1 (leaf-hacked leaf) invalid
        assertTrue(AttestationAnalysis.chainIsCryptographicallyBroken(3) { i -> i != 0 })
        assertTrue(AttestationAnalysis.chainIsCryptographicallyBroken(2) { false })
    }

    // --- 1b: attestation-vs-device contradiction ----------------------------

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
        // Attestation truthfully reports unlocked + unverified on a tampered
        // device -> no spoof, no flag.
        val rot = AttestationAnalysis.RootOfTrust(deviceLocked = false, verifiedBootState = 2)
        assertFalse(AttestationAnalysis.isBootContradiction(rot, deviceTampered = true))
    }

    // --- RootOfTrust DER parsing --------------------------------------------

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
        // OCTET STRING wrapping a SEQUENCE with an INTEGER but no [704].
        val keyDesc = tlv(0x30, tlv(0x02, byteArrayOf(0x01)))
        val ext = tlv(0x04, keyDesc)
        assertNull(AttestationAnalysis.parseRootOfTrust(ext))
    }

    // --- challenge anti-replay ----------------------------------------------

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

    // --- revocation (1d) logic ----------------------------------------------

    @Test
    fun normalizeSerialIsLowercaseHexNoLeadingZeros() {
        assertEquals("ff", AttestationAnalysis.normalizeSerial(BigInteger.valueOf(255)))
        assertEquals(
            "1234567890abcdef",
            AttestationAnalysis.normalizeSerial(BigInteger("1234567890abcdef", 16))
        )
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

    // --- 1c: chain anchoring to pinned Google roots -------------------------

    @Test
    fun chainEndingInPinnedRootAnchors() {
        val roots = AttestationRoots.pinnedRoots
        // A chain whose terminal cert IS a pinned root (SHA-256 match path).
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[0]), roots))
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[1]), roots))
    }

    @Test
    fun chainNotAnchoredWhenNoPinnedRootMatches() {
        val roots = AttestationRoots.pinnedRoots
        // RSA root is self-signed; it neither equals the EC root nor is signed
        // by it -> conclusively not anchored -> false (the flag condition).
        assertFalse(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[0]), listOf(roots[1])))
    }

    @Test
    fun anchorCheckFailsSafeOnEmptyInputs() {
        val roots = AttestationRoots.pinnedRoots
        // Inconclusive cases must return true (never flag).
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(emptyList(), roots))
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(roots[0]), emptyList()))
    }

    // --- real-device byte layouts (decoded from Google's keyattestation corpus) ---

    @Test
    fun parsesRealKeymasterRootOfTrustLayout() {
        // blueline sdk28: 302A( 0400 010100 0A0102 0420<32B> ) -- empty bootKey,
        // deviceLocked=false, verifiedBootState=Unverified(2).
        val rot = byteArrayOf(0x04, 0x00) +
            byteArrayOf(0x01, 0x01, 0x00) +
            byteArrayOf(0x0A, 0x01, 0x02) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(false, 2), parsed)
    }

    @Test
    fun parsesRealKeyMintRootOfTrustLayout() {
        // akita sdk34: 304A( 0420<32B> 010100 0A0102 0420<32B> ) -- 32B bootKey,
        // deviceLocked=false, verifiedBootState=Unverified(2).
        val rot = byteArrayOf(0x04, 0x20) + ByteArray(32) +
            byteArrayOf(0x01, 0x01, 0x00) +
            byteArrayOf(0x0A, 0x01, 0x02) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(false, 2), parsed)
    }

    @Test
    fun detectsForgedLockedVerifiedRootOfTrust() {
        // The invalid/malformed_rot_device_locked combo: 010101 (deviceLocked=TRUE)
        // + 0A0100 (verifiedBootState=Verified 0) -- exactly what a spoofer forges.
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
        // The actual inner DER of OID 1.3.6.1.4.1.11129.2.1.17 from Google's
        // testdata/akita/sdk34/TEE_EC_NONE.pem (KeyMint, Pixel 8). This is a
        // KeyDescription SEQUENCE; getExtensionValue() wraps it in an OCTET
        // STRING, so we wrap to mirror real input. Exercises: multi-byte
        // attestationVersion (0x012C = 300, two-byte INTEGER), positional
        // challenge extraction past it, software+hardware AuthorizationLists
        // (both carrying BF85xx tags), and hardwareEnforced-scoped [704] parse.
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
        val ext = tlv(0x04, keyDescription)  // mimic getExtensionValue() OCTET STRING wrap

        // challenge field (index 4) is the ASCII string "challenge"
        assertTrue(
            AttestationAnalysis.parseAttestationChallenge(ext)!!
                .contentEquals("challenge".toByteArray(Charsets.US_ASCII))
        )
        // RootOfTrust: deviceLocked=FALSE (0101 00), verifiedBootState=Unverified (0A01 02)
        assertEquals(
            AttestationAnalysis.RootOfTrust(false, 2),
            AttestationAnalysis.parseRootOfTrust(ext)
        )
    }

    @Test
    fun parsesRootOfTrustWithLongFormLengths() {
        // A 200-byte verifiedBootKey forces the RootOfTrust SEQUENCE (and the
        // wrappers above it) past 127 bytes, exercising readLength()'s long-form
        // branch that always runs against a real attestation extension.
        val rot = byteArrayOf(0x04.toByte(), 0x81.toByte(), 0xC8.toByte()) + ByteArray(200) +
            byteArrayOf(0x01, 0x01, 0x01) +
            byteArrayOf(0x0A, 0x01, 0x00) +
            byteArrayOf(0x04, 0x20) + ByteArray(32)
        val parsed = AttestationAnalysis.parseRootOfTrust(extensionWithRootOfTrust(rot))
        assertEquals(AttestationAnalysis.RootOfTrust(true, 0), parsed)
    }

    // --- DER fixture builders -----------------------------------------------

    /* KeyDescription with five fields so index 4 is the challenge OCTET STRING. */
    private fun buildExtensionWithChallenge(challenge: ByteArray): ByteArray {
        val keyDescription = tlv(
            0x30,
            tlv(0x02, byteArrayOf(0x03)) +           // [0] attestationVersion
                tlv(0x0A, byteArrayOf(0x01)) +        // [1] attestationSecurityLevel
                tlv(0x02, byteArrayOf(0x04)) +        // [2] keymasterVersion
                tlv(0x0A, byteArrayOf(0x01)) +        // [3] keymasterSecurityLevel
                tlv(0x04, challenge)                  // [4] attestationChallenge
        )
        return tlv(0x04, keyDescription)
    }

    /*
     * extensionValue = OCTET STRING { KeyDescription }, where KeyDescription is
     * SEQUENCE { INTEGER, SEQUENCE { [704] EXPLICIT { RootOfTrust } } } -- the
     * trailing nested SEQUENCE is the hardwareEnforced AuthorizationList the
     * parser scopes its [704] search to.
     */
    private fun buildExtension(deviceLocked: Boolean, verifiedBootState: Int): ByteArray {
        val rotSeqContent =
            tlv(0x04, byteArrayOf(0xAA.toByte(), 0xBB.toByte())) +          // verifiedBootKey
                tlv(0x01, byteArrayOf(if (deviceLocked) 0xFF.toByte() else 0x00)) + // deviceLocked
                tlv(0x0A, byteArrayOf(verifiedBootState.toByte())) +        // verifiedBootState
                tlv(0x04, byteArrayOf(0xCC.toByte(), 0xDD.toByte()))        // verifiedBootHash
        return extensionWithRootOfTrust(rotSeqContent)
    }

    /* Wrap raw RootOfTrust SEQUENCE *content* into a full extension value. */
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

    /* DER definite length: short form < 128, else minimal long form. */
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
