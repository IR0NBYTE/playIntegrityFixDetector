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

class AttestationChainForgeryTest {
    @Test
    fun forgedLeafWithAppendedPinnedRootIsRejected() {
        val attacker = ca("CN=Attacker")
        val forgedLeaf = leaf("CN=Forged", attacker.keyPair, attacker.privateKeySigner, isCa = false)
        val pinnedRoot = AttestationRoots.pinnedRoots.first()

        val chain = listOf(forgedLeaf, pinnedRoot)

        assertTrue(AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots))

        assertTrue(AttestationAnalysis.chainSignaturesBroken(chain))
    }

    @Test
    fun genuineSignaturesThroughNonCaIssuerAreRejected() {
        val root = ca("CN=Root")
        val endEntity = leafSignedBy("CN=RealAttestedKey", root, isCa = false)
        val forged = leafSignedBy("CN=Forged", endEntity, isCa = false)

        val chain = listOf(forged.cert, endEntity.cert, root.cert)

        assertFalse(AttestationAnalysis.chainSignaturesBroken(chain))

        assertTrue(AttestationAnalysis.chainHasNonCaIssuer(chain))
    }

    @Test
    fun unresolvableSignatureAlgorithmCountsAsBroken() {
        val root = ca("CN=Root")
        val bogus = leafSignedBy("CN=BogusAlg", root, isCa = false, algOid = UNKNOWN_SIG_ALG_OID)

        val chain = listOf(bogus.cert, root.cert)

        assertTrue(AttestationAnalysis.chainSignaturesBroken(chain))
    }

    @Test
    fun genuinelyShapedChainIsAccepted() {
        val root = ca("CN=Root")
        val intermediate = leafSignedBy("CN=Intermediate", root, isCa = true)
        val leaf = leafSignedBy("CN=Leaf", intermediate, isCa = false)

        val chain = listOf(leaf.cert, intermediate.cert, root.cert)

        assertFalse(AttestationAnalysis.chainSignaturesBroken(chain))
        assertFalse(AttestationAnalysis.chainHasNonCaIssuer(chain))
    }

    @Test
    fun singleCertChainIsNotJudged() {
        val root = ca("CN=Root")
        assertFalse(AttestationAnalysis.chainSignaturesBroken(listOf(root.cert)))
        assertFalse(AttestationAnalysis.chainHasNonCaIssuer(listOf(root.cert)))
    }

    @Test
    fun unrelatedSelfSignedRootDoesNotAnchor() {
        val root = ca("CN=NotGoogle")
        assertFalse(
            AttestationAnalysis.chainAnchorsToPinnedRoot(
                listOf(root.cert), AttestationRoots.pinnedRoots
            )
        )
    }

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
            explicit(0, int(2)) +
                int(nextSerial()) +
                algId +
                name(issuerDn) +
                validity() +
                name(subjectDn) +
                spki +

                if (isCa) explicit(3, seq(seq(basicConstraintsCa()))) else ByteArray(0)
        )

        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey)
            update(tbs)
            sign()
        }

        val der = seq(tbs + algId + bitString(sig))
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

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

        BASIC_CONSTRAINTS_OID +
            tlv(0x01, byteArrayOf(0xFF.toByte())) +
            tlv(0x04, seq(tlv(0x01, byteArrayOf(0xFF.toByte()))))

    private fun name(dn: String): ByteArray {
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
        val ECDSA_SHA256_OID = byteArrayOf(
            0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02
        )

        val UNKNOWN_SIG_ALG_OID = byteArrayOf(
            0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x63
        )

        val CN_OID = byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03)

        val BASIC_CONSTRAINTS_OID = byteArrayOf(0x06, 0x03, 0x55, 0x1D, 0x13)
    }
}
