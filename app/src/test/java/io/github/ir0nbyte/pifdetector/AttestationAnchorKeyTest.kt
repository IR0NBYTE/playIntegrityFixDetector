package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * What it means for a certificate to be an anchor, asserted on the real
 * published certificates rather than on stubs.
 *
 * Google issues one attestation key as several certificates with different
 * windows, and a handset goes on serving whichever instance it was provisioned
 * with. So the set of anchor BYTES a build embeds is only ever as complete as
 * the day it was assembled, while the set of anchor KEYS is stable. Every gate
 * here has to ask the stable question.
 *
 * The tests that matter most pass a deliberately narrowed pinned set, which is
 * how a build that has never seen a re-issued instance is simulated using only
 * certificates Google actually published.
 */
class AttestationAnchorKeyTest {

    private val RSA_2042 = "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"
    private val ECDSA_2035 = "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"
    private val RSA_2036 = "ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a"
    private val RSA_2034 = "1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc"
    private val RSA_2026 = "c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5"

    private val rsaInstances get() = listOf(RSA_2042, RSA_2036, RSA_2034, RSA_2026).map(::root)

    /** The set as it stood before this change: the current download only. */
    private val currentDownloadOnly get() = listOf(root(RSA_2042), root(ECDSA_2035))

    // ---- anchor keys -------------------------------------------------------

    @Test
    fun oneKeyIsDerivedForTheFourRsaInstances() {
        val keys = AttestationAnalysis.anchorKeyEncodings(rsaInstances)
        assertEquals(1, keys.size)
    }

    @Test
    fun theWholePinnedSetYieldsTwoKeys() {
        val keys = AttestationAnalysis.anchorKeyEncodings(AttestationRoots.pinnedRoots)
        assertEquals(2, keys.size)
    }

    @Test
    fun anEmptyPinnedSetYieldsNoKeys() {
        assertTrue(AttestationAnalysis.anchorKeyEncodings(emptyList()).isEmpty())
    }

    /**
     * The core of the fix. An instance this build does not embed still reads as
     * an anchor, because the key is what is compared.
     */
    @Test
    fun anInstanceThisBuildDoesNotPinStillCarriesAnAnchorKey() {
        val keys = AttestationAnalysis.anchorKeyEncodings(currentDownloadOnly)
        for (fingerprint in listOf(RSA_2036, RSA_2034, RSA_2026)) {
            assertTrue(
                "an unpinned re-issue of the anchor key must still read as an anchor",
                AttestationAnalysis.carriesAnchorKey(root(fingerprint), keys)
            )
        }
    }

    @Test
    fun aCertificateWithNoAnchorKeyIsNotAnAnchor() {
        val rsaOnly = AttestationAnalysis.anchorKeyEncodings(listOf(root(RSA_2042)))
        assertFalse(AttestationAnalysis.carriesAnchorKey(root(ECDSA_2035), rsaOnly))
    }

    /** With nothing pinned there is no anchor key, so nothing may claim to be one. */
    @Test
    fun nothingCarriesAnAnchorKeyWhenNothingIsPinned() {
        assertFalse(AttestationAnalysis.carriesAnchorKey(root(RSA_2042), emptySet()))
    }

    // ---- anchoring ---------------------------------------------------------

    @Test
    fun everyPublishedInstanceAnchors() {
        for (instance in rsaInstances + root(ECDSA_2035)) {
            assertTrue(
                "${instance.serialNumber.toString(16)} did not anchor",
                AttestationAnalysis.chainAnchorsToPinnedRoot(
                    listOf(instance), AttestationRoots.pinnedRoots
                )
            )
        }
    }

    /**
     * Anchoring already tolerated a pinned set narrower than what the device
     * serves, because it verifies the top under each anchor's key rather than
     * comparing bytes. That is why widening the set was never the fix on its
     * own, and it has to keep holding.
     */
    @Test
    fun anchoringToleratesAPinnedSetNarrowerThanTheServedInstance() {
        for (instance in rsaInstances) {
            assertTrue(
                AttestationAnalysis.chainAnchorsToPinnedRoot(
                    listOf(instance), currentDownloadOnly
                )
            )
        }
        assertFalse(
            "an ECDSA root must not anchor against the RSA key alone",
            AttestationAnalysis.chainAnchorsToPinnedRoot(
                listOf(root(ECDSA_2035)), listOf(root(RSA_2042))
            )
        )
    }

    /**
     * ChainValidity reads this as "no reference" rather than as a pass, so the
     * vacuous answer has to stay what it is.
     */
    @Test
    fun anEmptyPinnedSetAnchorsVacuously() {
        assertTrue(
            AttestationAnalysis.chainAnchorsToPinnedRoot(listOf(root(RSA_2042)), emptyList())
        )
    }

    // ---- revocation --------------------------------------------------------

    @Test
    fun noAnchorSerialIsEverSubmittedForRevocationLookup() {
        for (instance in rsaInstances + root(ECDSA_2035)) {
            assertEquals(
                "${instance.serialNumber.toString(16)} reached the revocation lookup",
                emptyList<String>(),
                RevocationChecker.serialKeysForChain(
                    listOf(instance), AttestationRoots.pinnedRoots
                )
            )
        }
    }

    /**
     * The regression this change exists for. Exclusion used to be by encoded
     * bytes, so a handset serving a re-issued root had the root's own serial
     * submitted for revocation lookup. No root serial is on the published list
     * today, so this was latent rather than a false positive anyone saw.
     */
    @Test
    fun anUnpinnedInstanceOfAnAnchorKeyIsStillKeptOutOfTheLookup() {
        for (fingerprint in listOf(RSA_2036, RSA_2034, RSA_2026)) {
            assertEquals(
                "a re-issued root this build does not embed reached the lookup",
                emptyList<String>(),
                RevocationChecker.serialKeysForChain(
                    listOf(root(fingerprint)), currentDownloadOnly
                )
            )
        }
    }

    /** A certificate that is not an anchor must still be looked up. */
    @Test
    fun aNonAnchorCertificateIsStillSubmitted() {
        val keys = RevocationChecker.serialKeysForChain(
            listOf(root(ECDSA_2035)), listOf(root(RSA_2042))
        )
        assertTrue("the ECDSA root is not an anchor here, so it must be looked up", keys.isNotEmpty())
    }

    // ---- validity ----------------------------------------------------------

    /**
     * Pinning older instances must not lower the time floor. The floor is the
     * latest instant every witness proves has passed, and a root's issue date
     * is one of those witnesses, so a careless change here would weaken the
     * expiry arms rather than widen the anchor set.
     */
    @Test
    fun pinningOlderInstancesDoesNotLowerTheTimeFloor() {
        val before = ChainValidity.timeFloor(emptyList(), currentDownloadOnly, emptyList(), null)
        val after = ChainValidity.timeFloor(
            emptyList(), AttestationRoots.pinnedRoots, emptyList(), null
        )
        assertTrue(before != null && after != null)
        assertTrue(
            "the floor dropped from $before to $after",
            after!! >= before!!
        )
        assertEquals("the newest pinned root still sets the floor", before, after)
    }

    /**
     * A lapsed anchor is never judged as an issuer. The 2016 instance expired
     * in May 2026 and a device provisioned with it still serves it, so leaving
     * it in the issuer set would accuse that device of an expired issuer.
     */
    @Test
    fun aLapsedAnchorInstanceIsNotJudgedAsAnIssuer() {
        val issuers = ChainValidity.issuerCertificates(
            listOf(root(RSA_2042), root(RSA_2026)), AttestationRoots.pinnedRoots
        )
        assertEquals(emptyList<X509Certificate>(), issuers)
    }

    /** The same holds when this build does not embed that instance. */
    @Test
    fun anUnpinnedAnchorInstanceIsNotJudgedAsAnIssuerEither() {
        val issuers = ChainValidity.issuerCertificates(
            listOf(root(RSA_2042), root(RSA_2034)), currentDownloadOnly
        )
        assertEquals(emptyList<X509Certificate>(), issuers)
    }

    private fun root(fingerprint: String): X509Certificate =
        AttestationRoots.pinnedRoots.first { sha256Hex(it.encoded) == fingerprint }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
