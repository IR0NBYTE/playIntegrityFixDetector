package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/*
 * Guards the embedded pinned root certificates. Trust-anchor correctness is the
 * whole point of 1c, so this asserts the PEMs in AttestationRoots both parse and
 * hash to the exact SHA-256(DER) fingerprints Google publishes at
 * https://android.googleapis.com/attestation/root. If a future root rotation
 * edits the PEMs, update these fingerprints in lockstep.
 */
class AttestationRootsTest {

    // openssl x509 -fingerprint -sha256, lowercased, colons stripped.
    private val RSA_ROOT_2042 =
        "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"
    private val ECDSA_ROOT_2035 =
        "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"

    @Test
    fun bothRootsParse() {
        assertEquals(2, AttestationRoots.pinnedRoots.size)
    }

    @Test
    fun fingerprintsMatchGooglePublishedRoots() {
        val fingerprints = AttestationRoots.pinnedRoots.map { sha256Hex(it.encoded) }.toSet()
        assertTrue("RSA 2042 root fingerprint missing", fingerprints.contains(RSA_ROOT_2042))
        assertTrue("ECDSA 2035 root fingerprint missing", fingerprints.contains(ECDSA_ROOT_2035))
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
