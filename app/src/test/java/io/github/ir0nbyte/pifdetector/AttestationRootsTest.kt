package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.cert.X509Certificate

/**
 * The pinned set itself, asserted against what Google publishes.
 *
 * The fingerprints are the identity of the certificates, so a mistyped or
 * re-wrapped PEM fails here rather than silently narrowing what this build
 * recognises as an anchor.
 */
class AttestationRootsTest {

    /** Currently published. */
    private val RSA_ROOT_2042 =
        "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"
    private val ECDSA_ROOT_2035 =
        "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"

    /** Previously issued, same RSA key as RSA_ROOT_2042. */
    private val RSA_ROOT_2036 =
        "ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a"
    private val RSA_ROOT_2034 =
        "1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc"
    private val RSA_ROOT_2026 =
        "c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5"

    private val rsaFingerprints =
        setOf(RSA_ROOT_2042, RSA_ROOT_2036, RSA_ROOT_2034, RSA_ROOT_2026)

    @Test
    fun everyPublishedRootParses() {
        assertEquals(5, AttestationRoots.pinnedRoots.size)
    }

    @Test
    fun fingerprintsMatchGooglePublishedRoots() {
        assertEquals(
            rsaFingerprints + ECDSA_ROOT_2035,
            AttestationRoots.pinnedRoots.map { sha256Hex(it.encoded) }.toSet()
        )
    }

    /**
     * The reason the set can be widened safely, and the reason widening it was
     * never the actual fix: the four RSA certificates are one key.
     */
    @Test
    fun theFourRsaRootsShareASingleKey() {
        val rsaKeys = AttestationRoots.pinnedRoots
            .filter { sha256Hex(it.encoded) in rsaFingerprints }
            .map { sha256Hex(it.publicKey.encoded) }
            .toSet()

        assertEquals(4, rsaFingerprints.size)
        assertEquals("the four RSA roots must be one key", 1, rsaKeys.size)
    }

    @Test
    fun theSetHoldsExactlyTwoDistinctKeys() {
        val keys = AttestationRoots.pinnedRoots.map { sha256Hex(it.publicKey.encoded) }.toSet()
        assertEquals(2, keys.size)
    }

    @Test
    fun theEcdsaRootIsADifferentKeyFromTheRsaRoots() {
        val rsa = byFingerprint(RSA_ROOT_2042).publicKey.encoded.toList()
        val ecdsa = byFingerprint(ECDSA_ROOT_2035).publicKey.encoded.toList()
        assertNotEquals(rsa, ecdsa)
    }

    /** A root that does not verify under its own key was transcribed wrong. */
    @Test
    fun everyPinnedRootIsSelfSigned() {
        for (root in AttestationRoots.pinnedRoots) {
            root.verify(root.publicKey)
            assertEquals(root.issuerX500Principal, root.subjectX500Principal)
        }
    }

    @Test
    fun everyPinnedRootIsACertificateAuthority() {
        for (root in AttestationRoots.pinnedRoots) {
            assertTrue(
                "${root.subjectX500Principal} is not a CA",
                root.basicConstraints >= 0
            )
        }
    }

    /**
     * Serial numbers are the publisher's own identifiers for the instances, so
     * they pin which five certificates these are independently of the digests.
     */
    @Test
    fun serialNumbersAreThePublishedInstances() {
        val serials = AttestationRoots.pinnedRoots
            .map { it.serialNumber.toString(16).lowercase() }
            .toSet()
        assertEquals(
            setOf(
                "f1c172a699eaf51d",              // 2022
                "84a9d0297b0eb58ae7ff0e80de760605", // CA1
                "c36b7c44b9ae1831",              // 2021
                "d50ff25ba3f2d6b3",              // 2019
                "e8fa196314d2fa18",              // 2016
            ),
            serials
        )
    }

    /**
     * The 2016 instance lapsed in May 2026 and is pinned deliberately. A device
     * provisioned with it still serves it, and an anchor is a statement about
     * provenance rather than about a window.
     */
    @Test
    fun aLapsedInstanceIsPinnedOnPurpose() {
        val lapsed = byFingerprint(RSA_ROOT_2026)
        assertTrue(
            "the 2016 instance should have lapsed by now; check the fixture",
            lapsed.notAfter.time < System.currentTimeMillis()
        )
        assertTrue(AttestationRoots.pinnedRoots.contains(lapsed))
    }

    /** Nothing in the pinned set may be a duplicate of another entry. */
    @Test
    fun thePinnedSetHasNoRepeatedCertificate() {
        val encodings = AttestationRoots.pinnedRoots.map { it.encoded.toList() }
        assertEquals(encodings.size, encodings.toSet().size)
    }

    /** An empty set turns every anchoring question vacuously true. */
    @Test
    fun thePinnedSetIsNeverEmpty() {
        assertFalse(AttestationRoots.pinnedRoots.isEmpty())
    }

    private fun byFingerprint(fingerprint: String): X509Certificate =
        AttestationRoots.pinnedRoots.first { sha256Hex(it.encoded) == fingerprint }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
