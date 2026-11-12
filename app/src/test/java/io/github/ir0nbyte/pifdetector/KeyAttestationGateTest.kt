package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.cert.X509Certificate

/**
 * Gate 3, the chain that is neither software nor anchored to a pinned Google
 * root. Only one shape is reported rather than convicted: a chain whose top is
 * a self-signed root this build does not recognise. A root Google adds with a
 * new key, or an OEM attesting to its own root, looks exactly like that, and
 * the project rule is that an unrecognised root must not read as a forgery.
 */
class KeyAttestationGateTest {

    private val year2024 = 1_704_067_200_000L
    private val year2030 = 1_893_456_000_000L

    private val googleKey = ChainValidityTest.StubKey("google-root")
    private val softwareKey = ChainValidityTest.StubKey("aosp-software-root")
    private val googleKeys = AttestationAnalysis.anchorKeyEncodings(
        listOf(cert("CN=google", googleKey, selfSigned = true))
    )
    private val softwareKeys = AttestationAnalysis.anchorKeyEncodings(
        listOf(cert("CN=aosp", softwareKey, selfSigned = true))
    )

    private val leaf = cert("CN=leaf", ChainValidityTest.StubKey("leaf"))

    private fun cert(
        subject: String,
        key: java.security.PublicKey = ChainValidityTest.StubKey(subject),
        selfSigned: Boolean = false,
        verifies: Boolean = true,
    ): X509Certificate =
        ChainValidityTest.StubCert(subject, year2024, year2030, key, selfSigned, verifies)

    private fun reportOnly(chain: List<X509Certificate>) =
        KeyAttestationProbe.unanchoredChainIsReportOnly(chain, googleKeys, softwareKeys)

    @Test
    fun anUnrecognisedSelfSignedRootIsReportedNotConvicted() {
        val oemRoot = cert("CN=some OEM root", selfSigned = true)
        assertTrue(reportOnly(listOf(leaf, oemRoot)))
        assertTrue(reportOnly(listOf(leaf, cert("CN=batch"), oemRoot)))
    }

    /** The AOSP software root under a record that does not say software stays 1203. */
    @Test
    fun anAospSoftwareRootUnderAHardwareClaimStaysAnAnomaly() {
        val aosp = cert("CN=aosp instance", softwareKey, selfSigned = true)
        assertFalse(reportOnly(listOf(leaf, aosp)))
    }

    @Test
    fun aTopThatIsNotSelfSignedStaysAnAnomaly() {
        assertFalse(reportOnly(listOf(leaf, cert("CN=dangling intermediate"))))
    }

    @Test
    fun aTopThatNamesItselfButDoesNotVerifyUnderItsOwnKeyStaysAnAnomaly() {
        val fake = cert("CN=fake root", selfSigned = true, verifies = false)
        assertFalse(reportOnly(listOf(leaf, fake)))
    }

    /** A lone certificate is the attested key itself, never a root. */
    @Test
    fun aSingleCertificateChainStaysAnAnomaly() {
        assertFalse(reportOnly(listOf(cert("CN=lone", selfSigned = true))))
        assertFalse(reportOnly(emptyList()))
    }

    /** A keystore that does not echo its challenge is a finding under any root. */
    @Test
    fun aReportOnlyChainStillAnswersForTheChallenge() {
        assertEquals(
            KeyAttestationProbe.REASON_CHALLENGE_MISMATCH,
            KeyAttestationProbe.unanchoredChainReason(reportOnly = true, challengeMismatched = true),
        )
        assertEquals(null, KeyAttestationProbe.unanchoredChainReason(true, false))
        assertEquals(
            KeyAttestationProbe.REASON_NEITHER_SOFTWARE_NOR_ANCHORED,
            KeyAttestationProbe.unanchoredChainReason(false, false),
        )
        assertEquals(
            KeyAttestationProbe.REASON_NEITHER_SOFTWARE_NOR_ANCHORED,
            KeyAttestationProbe.unanchoredChainReason(false, true),
        )
    }

    @Test
    fun aRecognisedGoogleRootIsNotThisCase() {
        val google = cert("CN=google instance", googleKey, selfSigned = true)
        assertFalse(reportOnly(listOf(leaf, google)))
    }

    // ---- the row -----------------------------------------------------------

    private fun anomalyRow(bitmask: Int, rootUnrecognised: Boolean) =
        DetectionResult.fromBitmask(bitmask, rootUnrecognised = rootUnrecognised)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_ANOMALY }

    @Test
    fun anUnrecognisedRootRendersAsUnverifiable() {
        val row = anomalyRow(0, rootUnrecognised = true)
        assertEquals(CheckState.UNVERIFIABLE, row.state)
        assertFalse(row.detected)
        assertTrue(row.detail!!.contains("does not recognise"))
        assertTrue(row.detail!!.contains("nothing in the record was judged"))
    }

    @Test
    fun anUnrecognisedRootNeverSoftensADetectedRow() {
        val row = anomalyRow(DetectionResult.DETECTION_ATTEST_ANOMALY, rootUnrecognised = true)
        assertEquals(CheckState.DETECTED, row.state)
    }

    @Test
    fun withoutTheFlagTheRowIsUnchanged() {
        assertEquals(CheckState.CLEAN, anomalyRow(0, rootUnrecognised = false).state)
    }

    @Test
    fun theFlagTouchesNoOtherRow() {
        val with = DetectionResult.fromBitmask(0, rootUnrecognised = true)
        val without = DetectionResult.fromBitmask(0)
        assertEquals(
            without.filter { it.flag != DetectionResult.DETECTION_ATTEST_ANOMALY },
            with.filter { it.flag != DetectionResult.DETECTION_ATTEST_ANOMALY },
        )
    }
}
