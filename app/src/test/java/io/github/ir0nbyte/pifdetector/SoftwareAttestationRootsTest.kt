package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * The AOSP software roots, asserted against the bytes AOSP compiles in.
 *
 * These certificates decide whether an arm fires, so a mistyped or re-wrapped
 * PEM has to fail here rather than quietly leave the arm unable to recognise
 * the thing it exists to recognise.
 */
class SoftwareAttestationRootsTest {

    /** kEcAttestRootCert in contexts/soft_attestation_cert.cpp. */
    private val EC_SOFTWARE_ROOT =
        "51d496ad4664190fbdaf1ad987278efa35d6fbf52e50a9c34ded8395477ede5c"

    /** kRsaAttestRootCert in the same file. */
    private val RSA_SOFTWARE_ROOT =
        "4e42730efd521b21d77b109b7532a0b664ddfefc73e129111936200c5e58cce0"

    @Test
    fun bothRootsParse() {
        assertEquals(2, SoftwareAttestationRoots.roots.size)
    }

    @Test
    fun fingerprintsMatchTheAospSource() {
        val md = MessageDigest.getInstance("SHA-256")
        val actual = SoftwareAttestationRoots.roots
            .map { md.digest(it.encoded).joinToString("") { b -> "%02x".format(b) } }
            .toSet()
        assertEquals(setOf(EC_SOFTWARE_ROOT, RSA_SOFTWARE_ROOT), actual)
    }

    /** Both are self-signed, which is what makes isAnchorInstance usable. */
    @Test
    fun bothRootsAreSelfSigned() {
        for (root in SoftwareAttestationRoots.roots) {
            assertEquals(root.subjectX500Principal, root.issuerX500Principal)
        }
    }

    /**
     * The whole premise of [CompanionAlgorithmCheck]: AOSP does not use one
     * root for both algorithms, so root equality is not a platform invariant
     * and must never be the arm.
     */
    @Test
    fun theTwoSoftwareRootsAreDifferentKeys() {
        val keys = SoftwareAttestationRoots.roots.map { it.publicKey.encoded.toList() }
        assertEquals(2, keys.size)
        assertNotEquals(keys[0], keys[1])
    }

    /** A software root is a label, never a trust anchor. */
    @Test
    fun noSoftwareRootIsAlsoPinnedAsAnAnchor() {
        val anchorKeys = AttestationAnalysis.anchorKeyEncodings(AttestationRoots.pinnedRoots)
        assertTrue(anchorKeys.isNotEmpty())
        for (root in SoftwareAttestationRoots.roots) {
            assertTrue(
                "an AOSP software root is in the pinned anchor set",
                !AttestationAnalysis.carriesAnchorKey(root, anchorKeys)
            )
        }
    }
}
