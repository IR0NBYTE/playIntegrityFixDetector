package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hostile DER inside an otherwise well-formed record.
 *
 * Every fixture is a KeyDescription with all eight members, because the
 * parsers refuse any other member count before they look inside a list. An
 * earlier version of this file used records with two members, so each
 * assertion passed on the member-count guard and the hostile bytes were never
 * read. Here the hostile bytes sit in member 7, the hardwareEnforced list, or
 * in member 4, the challenge, and every hostile fixture has a benign twin that
 * differs only in those bytes and does parse. The twin is what proves the
 * hostile bytes were reached.
 */
class AttestationHostileDerTest {

    // ---- the length overflow -------------------------------------------------

    /** A SEQUENCE claiming 0x7FFFFFFF bytes inside a list that holds six. */
    private val overflowTlv = byteArrayOf(
        0x30, 0x84.toByte(), 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
    )

    @Test
    fun parseRootOfTrustSurvivesLengthOverflow() {
        assertNotNull(AttestationAnalysis.parseRootOfTrust(record(hardwareEnforced = list(rotTlv))))
        assertNull(
            AttestationAnalysis.parseRootOfTrust(record(hardwareEnforced = list(rotTlv, overflowTlv)))
        )
    }

    @Test
    fun hasHardwareEnforcedTagSurvivesLengthOverflow() {
        val tag = AttestationAnalysis.TAG_NO_AUTH_REQUIRED
        assertTrue(
            AttestationAnalysis.hasHardwareEnforcedTag(record(hardwareEnforced = list(noAuthTlv)), tag)
        )
        assertFalse(
            AttestationAnalysis.hasHardwareEnforcedTag(
                record(hardwareEnforced = list(overflowTlv, noAuthTlv)), tag
            )
        )
    }

    /** The overflow in member 4 itself, the challenge. */
    @Test
    fun parseAttestationChallengeSurvivesLengthOverflow() {
        val benign = AttestationAnalysis.parseAttestationChallenge(record())
        assertArrayEquals(CHALLENGE, benign)
        val hostileChallenge = byteArrayOf(
            0x04, 0x84.toByte(), 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
        )
        assertNull(AttestationAnalysis.parseAttestationChallenge(record(challenge = hostileChallenge)))
    }

    // ---- deep nesting --------------------------------------------------------

    /**
     * A RootOfTrust whose SEQUENCE holds ten thousand nested SEQUENCEs instead
     * of its fields. The parser reads the RootOfTrust's immediate members only,
     * so it finds no fields and returns null rather than descending.
     */
    @Test
    fun parseRootOfTrustSurvivesDeepNesting() {
        assertNotNull(AttestationAnalysis.parseRootOfTrust(record(hardwareEnforced = list(rotTlv))))
        val hostileRot = tlv(ROT_TAG, deeplyNested(10_000))
        assertNull(
            AttestationAnalysis.parseRootOfTrust(record(hardwareEnforced = list(hostileRot)))
        )
    }

    /**
     * Ten thousand nested SEQUENCEs ahead of noAuthRequired in the list. The
     * list walk steps over them by length and still finds the tag, which is
     * what the benign twin finds, so the hostile member was walked and not
     * descended.
     */
    @Test
    fun authRequirementContradictionSurvivesDeepNesting() {
        assertTrue(
            AttestationAnalysis.authRequirementContradiction(record(hardwareEnforced = list(noAuthTlv)))
        )
        assertTrue(
            AttestationAnalysis.authRequirementContradiction(
                record(hardwareEnforced = list(deeplyNested(10_000), noAuthTlv))
            )
        )
    }

    // ---- a truncated high tag number ------------------------------------------

    /**
     * A final list member that is one byte, 0xBF, announcing a multi-byte tag
     * number that never arrives. The list scan reads past a match to reject
     * duplicates, so the truncated tag is reached after the real RootOfTrust.
     */
    @Test
    fun parseRootOfTrustSurvivesTruncatedHighTagNumber() {
        assertNotNull(AttestationAnalysis.parseRootOfTrust(record(hardwareEnforced = list(rotTlv))))
        assertNull(
            AttestationAnalysis.parseRootOfTrust(
                record(hardwareEnforced = list(rotTlv, byteArrayOf(0xBF.toByte())))
            )
        )
    }

    @Test
    fun benignExtensionStillParses() {
        val rot = AttestationAnalysis.parseRootOfTrust(realAkitaExtension())
        val parsed = requireNotNull(rot) { "benign KeyMint extension must still parse" }
        assertFalse(parsed.deviceLocked)
    }

    // ---- builders --------------------------------------------------------------

    private companion object {
        val CHALLENGE = "challenge".toByteArray()

        /** Tag 704, the RootOfTrust, as context-specific constructed. */
        val ROT_TAG = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40)

        /** Tag 503, noAuthRequired, holding a NULL. */
        val noAuthTlv = byteArrayOf(0xBF.toByte(), 0x83.toByte(), 0x77, 0x02, 0x05, 0x00)

        /** The RootOfTrust from the real Akita record below. */
        val rotTlv = hex(
            "BF85404C304A0420" + "00".repeat(32) + "0101000A01020420" +
                "882588576475AECCB392982FE2FBC5F62C69C9FC84BA73E6C53CC052A1161586"
        )

        fun hex(s: String): ByteArray =
            ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        fun derLength(n: Int): ByteArray = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n <= 0xFF -> byteArrayOf(0x81.toByte(), n.toByte())
            n <= 0xFFFF -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf(
                0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte()
            )
        }

        fun tlv(tag: ByteArray, content: ByteArray): ByteArray =
            tag + derLength(content.size) + content

        fun list(vararg members: ByteArray): ByteArray =
            tlv(byteArrayOf(0x30), members.fold(ByteArray(0)) { acc, m -> acc + m })

        /**
         * An 8-member KeyDescription wrapped in the extension's OCTET STRING:
         * attestationVersion 100, TrustedEnvironment, keyMintVersion 100,
         * TrustedEnvironment, the challenge, an empty uniqueId, an empty
         * softwareEnforced list and the given hardwareEnforced list.
         */
        fun record(
            challenge: ByteArray = tlv(byteArrayOf(0x04), CHALLENGE),
            hardwareEnforced: ByteArray = list(),
        ): ByteArray {
            val members = byteArrayOf(0x02, 0x01, 0x64) +
                byteArrayOf(0x0A, 0x01, 0x01) +
                byteArrayOf(0x02, 0x01, 0x64) +
                byteArrayOf(0x0A, 0x01, 0x01) +
                challenge +
                byteArrayOf(0x04, 0x00) +
                list() +
                hardwareEnforced
            return tlv(byteArrayOf(0x04), tlv(byteArrayOf(0x30), members))
        }

        fun deeplyNested(depth: Int): ByteArray {
            var body = byteArrayOf(0x30, 0x00)
            repeat(depth) { body = tlv(byteArrayOf(0x30), body) }
            return body
        }

        fun realAkitaExtension(): ByteArray {
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
            return tlv(byteArrayOf(0x04), keyDescription)
        }
    }
}
