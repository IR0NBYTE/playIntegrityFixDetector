package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/*
 * Chain-validation tests driven by REAL certificates and REAL signatures.
 *
 * Everything else in the suite drives chainIsCryptographicallyBroken through a
 * boolean stub, so until now no test ever executed the verification itself, and
 * the chain shapes a keybox spoofer actually produces went unexercised. Each
 * test here builds the exact shape and asserts the verdict.
 *
 * Certificates are assembled by hand rather than with BouncyCastle so the test
 * suite stays dependency-free; only java.security does the crypto.
 */
class AttestationChainForgeryTest {

    /*
     * The shape that defeated the active probe: a forged leaf with a copy of a
     * pinned Google root appended. The roots ship inside the APK, so pasting one
     * costs an attacker nothing, and an anchor check that only looks at
     * chain.last() is satisfied by it.
     */
    @Test
    fun forgedLeafWithAppendedPinnedRootIsRejected() {
        val attacker = ca("CN=Attacker")
        val forgedLeaf = leaf("CN=Forged", attacker.keyPair, attacker.privateKeySigner, isCa = false)
        val pinnedRoot = AttestationRoots.pinnedRoots.first()

        val chain = listOf(forgedLeaf, pinnedRoot)

        // The anchor check alone is happy: the top cert IS a pinned root.
        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots))
        // Signature validation is what actually rejects it.
        assertTrue(AttestationAnalysis.chainSignaturesBroken(chain))
    }

    /*
     * The subtler shape: every signature is genuine and the chain really does
     * terminate at a trusted root, but one link is an end-entity certificate.
     * An ordinary attested key from a real device is exactly that, and its
     * private key lives in the attacker's own Keystore, so they can sign a
     * forged leaf with it.
     */
    @Test
    fun genuineSignaturesThroughNonCaIssuerAreRejected() {
        val root = ca("CN=Root")
        val endEntity = leafSignedBy("CN=RealAttestedKey", root, isCa = false)
        val forged = leafSignedBy("CN=Forged", endEntity, isCa = false)

        val chain = listOf(forged.cert, endEntity.cert, root.cert)

        // Every link verifies -- signature validation cannot see this one.
        assertFalse(AttestationAnalysis.chainSignaturesBroken(chain))
        // basicConstraints is what rejects it.
        assertTrue(AttestationAnalysis.chainHasNonCaIssuer(chain))
    }

    /*
     * A leaf whose signature algorithm OID the platform cannot resolve. verify()
     * raises NoSuchAlgorithmException, which used to be treated as "could not
     * check" and therefore as a valid link -- a free bypass, since the OID is
     * written by whoever forged the certificate.
     */
    @Test
    fun unresolvableSignatureAlgorithmCountsAsBroken() {
        val root = ca("CN=Root")
        val bogus = leafSignedBy("CN=BogusAlg", root, isCa = false, algOid = UNKNOWN_SIG_ALG_OID)

        val chain = listOf(bogus.cert, root.cert)

        assertTrue(AttestationAnalysis.chainSignaturesBroken(chain))
    }

    /* A well-formed chain must survive all of the above unflagged. */
    @Test
    fun genuinelyShapedChainIsAccepted() {
        val root = ca("CN=Root")
        val intermediate = leafSignedBy("CN=Intermediate", root, isCa = true)
        val leaf = leafSignedBy("CN=Leaf", intermediate, isCa = false)

        val chain = listOf(leaf.cert, intermediate.cert, root.cert)

        assertFalse(AttestationAnalysis.chainSignaturesBroken(chain))
        assertFalse(AttestationAnalysis.chainHasNonCaIssuer(chain))
    }

    /* A chain of one cannot be cryptographically judged and must not flag. */
    @Test
    fun singleCertChainIsNotJudged() {
        val root = ca("CN=Root")
        assertFalse(AttestationAnalysis.chainSignaturesBroken(listOf(root.cert)))
        assertFalse(AttestationAnalysis.chainHasNonCaIssuer(listOf(root.cert)))
    }

    /* A self-signed root that is not one of ours must not anchor. */
    @Test
    fun unrelatedSelfSignedRootDoesNotAnchor() {
        val root = ca("CN=NotGoogle")
        assertFalse(
            AttestationAnalysis.chainAnchorsToPinnedRoot(
                listOf(root.cert), AttestationRoots.pinnedRoots
            )
        )
    }

    // --- minimal X.509 builder ----------------------------------------------

    private class Issued(
        val cert: X509Certificate,
        val keyPair: KeyPair
    ) {
        val privateKeySigner: PrivateKey get() = keyPair.private
    }

    private fun ca(dn: String): Issued {
        val kp = generateKeyPair()
        val cert = build(dn, dn, kp.public.encoded, kp.private, isCa = true, algOid = ECDSA_SHA256_OID)
        return Issued(cert, kp)
    }

    private fun leafSignedBy(
        dn: String,
        issuer: Issued,
        isCa: Boolean,
        algOid: ByteArray = ECDSA_SHA256_OID
    ): Issued {
        val kp = generateKeyPair()
        val cert = build(
            subjectDn = dn,
            issuerDn = issuer.cert.subjectX500Principal.name,
            spki = kp.public.encoded,
            signingKey = issuer.keyPair.private,
            isCa = isCa,
            algOid = algOid
        )
        return Issued(cert, kp)
    }

    private fun leaf(
        dn: String,
        kp: KeyPair,
        signingKey: PrivateKey,
        isCa: Boolean
    ): X509Certificate =
        build(dn, dn, kp.public.encoded, signingKey, isCa, ECDSA_SHA256_OID)

    private fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    private fun build(
        subjectDn: String,
        issuerDn: String,
        spki: ByteArray,
        signingKey: PrivateKey,
        isCa: Boolean,
        algOid: ByteArray
    ): X509Certificate {
        val algId = seq(algOid)
        val tbs = seq(
            explicit(0, int(2)) +                       // version v3
                int(nextSerial()) +
                algId +
                name(issuerDn) +
                validity() +
                name(subjectDn) +
                spki +
                // [3] EXPLICIT Extensions ::= SEQUENCE OF Extension,
                // and each Extension is itself a SEQUENCE.
                if (isCa) explicit(3, seq(seq(basicConstraintsCa()))) else ByteArray(0)
        )

        // Always sign with a real algorithm; only the DECLARED OID varies, which
        // is what an attacker controls.
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey)
            update(tbs)
            sign()
        }

        val der = seq(tbs + algId + bitString(sig))
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    // --- DER primitives ------------------------------------------------------

    private var serialCounter = 1L
    private fun nextSerial(): Long = serialCounter++

    private fun len(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), (n and 0xFF).toByte())
    }

    private fun tlv(tag: Int, body: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + len(body.size) + body

    private fun seq(body: ByteArray): ByteArray = tlv(0x30, body)
    private fun set(body: ByteArray): ByteArray = tlv(0x31, body)
    private fun explicit(n: Int, body: ByteArray): ByteArray = tlv(0xA0 or n, body)
    private fun bitString(body: ByteArray): ByteArray = tlv(0x03, byteArrayOf(0) + body)

    private fun int(v: Long): ByteArray {
        var bytes = BigInteger.valueOf(v).toByteArray()
        if (bytes.isEmpty()) bytes = byteArrayOf(0)
        return tlv(0x02, bytes)
    }

    private fun basicConstraintsCa(): ByteArray =
        // Extension ::= SEQUENCE { extnID, critical, extnValue }
        BASIC_CONSTRAINTS_OID +
            tlv(0x01, byteArrayOf(0xFF.toByte())) +          // critical TRUE
            tlv(0x04, seq(tlv(0x01, byteArrayOf(0xFF.toByte()))))  // cA TRUE

    private fun name(dn: String): ByteArray {
        // Only CN=<value> is used by these fixtures.
        val cn = dn.substringAfter("CN=").substringBefore(",").trim()
        return seq(set(seq(CN_OID + tlv(0x0C, cn.toByteArray()))))
    }

    private fun validity(): ByteArray {
        val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val now = System.currentTimeMillis()
        val notBefore = fmt.format(Date(now - 86_400_000L))
        val notAfter = fmt.format(Date(now + 365L * 86_400_000L))
        return seq(
            tlv(0x17, notBefore.toByteArray()) + tlv(0x17, notAfter.toByteArray())
        )
    }

    private companion object {
        /* ecdsa-with-SHA256, 1.2.840.10045.4.3.2 */
        val ECDSA_SHA256_OID = byteArrayOf(
            0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02
        )

        /* 1.2.840.10045.4.3.99 -- deliberately not a real algorithm. */
        val UNKNOWN_SIG_ALG_OID = byteArrayOf(
            0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x63
        )

        /* id-at-commonName, 2.5.4.3 */
        val CN_OID = byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03)

        /* id-ce-basicConstraints, 2.5.29.19 */
        val BASIC_CONSTRAINTS_OID = byteArrayOf(0x06, 0x03, 0x55, 0x1D, 0x13)
    }
}
