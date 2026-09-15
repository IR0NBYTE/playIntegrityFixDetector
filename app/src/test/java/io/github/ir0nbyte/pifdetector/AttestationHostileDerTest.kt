package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class AttestationHostileDerTest {
    private val overflowLength = byteArrayOf(
        0x04, 0x0D,
        0x30, 0x0B,
        0x02, 0x01, 0x03,
        0x30, 0x06,
        0x30, 0x84.toByte(), 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
    )

    private fun deeplyNested(depth: Int): ByteArray {
        var body = byteArrayOf(0x30, 0x00)
        repeat(depth) {
            body = if (body.size < 0x80) {
                byteArrayOf(0x30, body.size.toByte()) + body
            } else {
                byteArrayOf(
                    0x30, 0x82.toByte(),
                    ((body.size shr 8) and 0xFF).toByte(),
                    (body.size and 0xFF).toByte()
                ) + body
            }
        }

        val keyDescription = byteArrayOf(0x02, 0x01, 0x03) + body
        val seq = byteArrayOf(
            0x30, 0x82.toByte(),
            ((keyDescription.size shr 8) and 0xFF).toByte(),
            (keyDescription.size and 0xFF).toByte()
        ) + keyDescription
        return byteArrayOf(
            0x04, 0x82.toByte(),
            ((seq.size shr 8) and 0xFF).toByte(),
            (seq.size and 0xFF).toByte()
        ) + seq
    }

    private val truncatedHighTag = byteArrayOf(
        0x04, 0x08,
        0x30, 0x06,
        0x02, 0x01, 0x03,
        0x30, 0x01,
        0xBF.toByte()
    )

    @Test
    fun parseRootOfTrustSurvivesLengthOverflow() {
        assertNull(AttestationAnalysis.parseRootOfTrust(overflowLength))
    }

    @Test
    fun parseAttestationChallengeSurvivesLengthOverflow() {
        assertNull(AttestationAnalysis.parseAttestationChallenge(overflowLength))
    }

    @Test
    fun hasHardwareEnforcedTagSurvivesLengthOverflow() {
        assertFalse(
            AttestationAnalysis.hasHardwareEnforcedTag(
                overflowLength, AttestationAnalysis.TAG_NO_AUTH_REQUIRED
            )
        )
    }

    @Test
    fun parseRootOfTrustSurvivesDeepNesting() {
        assertNull(AttestationAnalysis.parseRootOfTrust(deeplyNested(10_000)))
    }

    @Test
    fun authRequirementContradictionSurvivesDeepNesting() {
        assertFalse(AttestationAnalysis.authRequirementContradiction(deeplyNested(10_000)))
    }

    @Test
    fun parseRootOfTrustSurvivesTruncatedHighTagNumber() {
        assertNull(AttestationAnalysis.parseRootOfTrust(truncatedHighTag))
    }

    @Test
    fun benignExtensionStillParses() {
        val rot = AttestationAnalysis.parseRootOfTrust(realAkitaExtension())
        val parsed = requireNotNull(rot) { "benign KeyMint extension must still parse" }
        assertFalse(parsed.deviceLocked)
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
        return byteArrayOf(0x04, 0x82.toByte(),
            ((keyDescription.size shr 8) and 0xFF).toByte(),
            (keyDescription.size and 0xFF).toByte()) + keyDescription
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
