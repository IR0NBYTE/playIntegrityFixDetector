package io.github.ir0nbyte.pifdetector

import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.X509Certificate

object AttestationAnalysis {
    const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    const val VERIFIED_BOOT_STATE_VERIFIED = 0

    data class RootOfTrust(val deviceLocked: Boolean, val verifiedBootState: Int)

    fun chainIsCryptographicallyBroken(certCount: Int, verifyLink: (childIndex: Int) -> Boolean): Boolean {
        if (certCount < 2) return false
        for (i in 0 until certCount - 1) {
            if (!verifyLink(i)) return true
        }
        return false
    }

    fun isBootContradiction(rot: RootOfTrust?, deviceTampered: Boolean): Boolean {
        if (rot == null || !deviceTampered) return false
        val attestationClaimsClean =
            rot.deviceLocked || rot.verifiedBootState == VERIFIED_BOOT_STATE_VERIFIED
        return attestationClaimsClean
    }

    fun bootPropertiesContradictAttestation(
        rot: RootOfTrust?,
        propertiesClaimLocked: Boolean
    ): Boolean {
        if (rot == null || !propertiesClaimLocked) return false
        val attestationSaysTampered =
            !rot.deviceLocked || rot.verifiedBootState != VERIFIED_BOOT_STATE_VERIFIED
        return attestationSaysTampered
    }

    fun challengeMismatch(parsedChallenge: ByteArray?, expected: ByteArray): Boolean {
        if (parsedChallenge == null) return false
        return !parsedChallenge.contentEquals(expected)
    }

    fun chainAnchorsToPinnedRoot(
        chain: List<X509Certificate>,
        pinnedRoots: List<X509Certificate>
    ): Boolean {
        if (chain.isEmpty() || pinnedRoots.isEmpty()) return true
        return try {
            val top = chain.last()
            val md = MessageDigest.getInstance("SHA-256")
            val topDigest = md.digest(top.encoded)
            for (root in pinnedRoots) {
                if (topDigest.contentEquals(md.digest(root.encoded))) return true
                try {
                    top.verify(root.publicKey)
                    return true
                } catch (_: Exception) {
                }
            }
            false
        } catch (_: Throwable) {
            true
        }
    }

    fun anyCertRevoked(chainSerials: List<String>, revokedSerials: Set<String>): Boolean {
        if (revokedSerials.isEmpty()) return false
        return chainSerials.any { revokedSerials.contains(it) }
    }

    fun normalizeSerial(serial: BigInteger): String = serial.abs().toString(16)

    fun serialLookupKeys(serial: BigInteger): List<String> {
        val positive = serial.abs()
        return listOf(positive.toString(16), positive.toString(10)).distinct()
    }

    fun chainSignaturesBroken(chain: List<X509Certificate>): Boolean =
        chainIsCryptographicallyBroken(chain.size) { i ->
            try {
                chain[i].verify(chain[i + 1].publicKey)
                true
            } catch (_: java.security.SignatureException) {
                false
            } catch (_: java.security.InvalidKeyException) {
                false
            } catch (_: java.security.NoSuchAlgorithmException) {
                false
            } catch (_: Throwable) {
                true
            }
        }

    fun chainHasNonCaIssuer(chain: List<X509Certificate>): Boolean {
        if (chain.size < 2) return false
        return try {
            (1 until chain.size).any { chain[it].basicConstraints < 0 }
        } catch (_: Throwable) {
            false
        }
    }

    const val TAG_NO_AUTH_REQUIRED = 503
    const val TAG_USER_AUTH_TYPE = 504
    const val TAG_AUTH_TIMEOUT = 505

    fun contextConstructedTag(tagNo: Int): ByteArray {
        if (tagNo < 0x1F) return byteArrayOf((0xA0 or tagNo).toByte())
        val digits = ArrayList<Int>()
        var v = tagNo
        while (v > 0) {
            digits.add(0, v and 0x7F)
            v = v shr 7
        }
        val out = ByteArray(1 + digits.size)
        out[0] = 0xBF.toByte()
        for (i in digits.indices) {
            val last = i == digits.size - 1
            out[i + 1] = (if (last) digits[i] else (digits[i] or 0x80)).toByte()
        }
        return out
    }

    fun hasHardwareEnforcedTag(extensionValue: ByteArray, tagNo: Int): Boolean {
        return try {
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return false
            val hardwareEnforced = lastSequenceChildContent(unwrapped) ?: return false
            findTaggedContent(hardwareEnforced, contextConstructedTag(tagNo)) != null
        } catch (_: Throwable) {
            false
        }
    }

    fun authRequirementContradiction(extensionValue: ByteArray): Boolean {
        val claimsNoAuth = hasHardwareEnforcedTag(extensionValue, TAG_NO_AUTH_REQUIRED)
        if (!claimsNoAuth) return false
        val hasAuthType = hasHardwareEnforcedTag(extensionValue, TAG_USER_AUTH_TYPE)
        val hasAuthTimeout = hasHardwareEnforcedTag(extensionValue, TAG_AUTH_TIMEOUT)
        return !hasAuthType && !hasAuthTimeout
    }

    fun leafSignatureTracksRequestedDigest(sigAlgName: String?): Boolean {
        if (sigAlgName.isNullOrBlank()) return false
        val normalized = sigAlgName.uppercase().replace("-", "")
        if (!normalized.contains("WITH")) return false
        return normalized.substringBefore("WITH") == "SHA512"
    }

    fun isSelfSignedSingleCert(chain: List<X509Certificate>): Boolean {
        if (chain.size != 1) return false
        return try {
            val cert = chain[0]
            cert.getExtensionValue(ATTESTATION_OID) != null &&
                cert.issuerX500Principal == cert.subjectX500Principal
        } catch (_: Throwable) {
            false
        }
    }

    fun parseAttestationChallenge(extensionValue: ByteArray): ByteArray? {
        return try {
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return null
            val r = Asn1Reader(unwrapped)
            val seqTag = r.readTag()
            if (seqTag.size != 1 || (seqTag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
            val seqLen = r.readLength()
            val inner = Asn1Reader(unwrapped, r.pos, r.pos + seqLen)
            var index = 0
            while (inner.hasMore()) {
                val tag = inner.readTag()
                val len = inner.readLength()
                val start = inner.pos
                inner.pos = start + len
                if (index == ATTESTATION_CHALLENGE_INDEX) {
                    return if (tag.size == 1 && (tag[0].toInt() and 0xFF) == TAG_OCTET_STRING) {
                        unwrapped.copyOfRange(start, start + len)
                    } else {
                        null
                    }
                }
                index++
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    fun parseAttestationSecurityLevel(extensionValue: ByteArray): Int? {
        return try {
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return null
            val r = Asn1Reader(unwrapped)
            val seqTag = r.readTag()
            if (seqTag.size != 1 || (seqTag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
            val seqLen = r.readLength()
            val inner = Asn1Reader(unwrapped, r.pos, r.pos + seqLen)
            var index = 0
            while (inner.hasMore()) {
                val tag = inner.readTag()
                val len = inner.readLength()
                val start = inner.pos
                inner.pos = start + len
                if (index == ATTESTATION_SECURITY_LEVEL_INDEX) {
                    return if (tag.size == 1 &&
                        (tag[0].toInt() and 0xFF) == TAG_ENUMERATED && len >= 1
                    ) {
                        unwrapped[start].toInt() and 0xFF
                    } else {
                        null
                    }
                }
                index++
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    fun parseRootOfTrust(extensionValue: ByteArray): RootOfTrust? {
        return try {
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return null

            val hardwareEnforced = lastSequenceChildContent(unwrapped) ?: return null
            val rotContent = findTaggedContent(hardwareEnforced, ROOT_OF_TRUST_TAG) ?: return null
            parseRootOfTrustSequence(rotContent)
        } catch (_: Throwable) {
            null
        }
    }

    private val ROOT_OF_TRUST_TAG = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40.toByte())

    private const val TAG_BOOLEAN = 0x01
    private const val TAG_OCTET_STRING = 0x04
    private const val TAG_ENUMERATED = 0x0A
    private const val TAG_SEQUENCE = 0x30

    private const val ATTESTATION_CHALLENGE_INDEX = 4
    private const val ATTESTATION_SECURITY_LEVEL_INDEX = 1

    const val SECURITY_LEVEL_SOFTWARE = 0
    const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
    const val SECURITY_LEVEL_STRONGBOX = 2

    private class Asn1Reader(val buf: ByteArray, var pos: Int = 0, val end: Int = buf.size) {
        fun hasMore(): Boolean = pos < end

        fun readTag(): ByteArray {
            val start = pos
            val first = buf[pos++].toInt() and 0xFF
            if (first and 0x1F == 0x1F) {
                while (pos < end && (buf[pos].toInt() and 0x80) != 0) pos++
                pos++

                if (pos > end) throw IllegalStateException("truncated tag")
            }
            return buf.copyOfRange(start, pos)
        }

        fun isConstructed(tag: ByteArray): Boolean = (tag[0].toInt() and 0x20) != 0

        fun readLength(): Int {
            var len = buf[pos++].toInt() and 0xFF
            if (len and 0x80 != 0) {
                val numBytes = len and 0x7F
                if (numBytes == 0 || numBytes > 4) throw IllegalStateException("bad length")
                len = 0
                repeat(numBytes) { len = (len shl 8) or (buf[pos++].toInt() and 0xFF) }
            }

            if (len < 0 || pos.toLong() + len.toLong() > end.toLong())
                throw IllegalStateException("length overflow")
            return len
        }
    }

    private fun lastSequenceChildContent(seqTlv: ByteArray): ByteArray? {
        val r = Asn1Reader(seqTlv)
        val tag = r.readTag()
        if (tag.size != 1 || (tag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
        val len = r.readLength()
        val inner = Asn1Reader(seqTlv, r.pos, r.pos + len)
        var lastStart = -1
        var lastEnd = -1
        while (inner.hasMore()) {
            inner.readTag()
            val l = inner.readLength()
            val start = inner.pos
            inner.pos = start + l
            lastStart = start
            lastEnd = start + l
        }
        if (lastStart < 0) return null
        return seqTlv.copyOfRange(lastStart, lastEnd)
    }

    private fun readSingleOctetStringContent(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null
        val r = Asn1Reader(data)
        val tag = r.readTag()
        if (tag.size != 1 || (tag[0].toInt() and 0xFF) != TAG_OCTET_STRING) return null
        val len = r.readLength()
        return data.copyOfRange(r.pos, r.pos + len)
    }

    private const val MAX_DER_DEPTH = 20

    private fun findTaggedContent(
        data: ByteArray,
        target: ByteArray,
        depth: Int = 0
    ): ByteArray? {
        if (depth > MAX_DER_DEPTH) return null
        val r = Asn1Reader(data)
        while (r.hasMore()) {
            val tag = r.readTag()
            val len = r.readLength()
            val contentStart = r.pos
            val content = data.copyOfRange(contentStart, contentStart + len)
            r.pos = contentStart + len

            if (tag.contentEquals(target)) return content
            if (r.isConstructed(tag)) {
                val nested = findTaggedContent(content, target, depth + 1)
                if (nested != null) return nested
            }
        }
        return null
    }

    private fun parseRootOfTrustSequence(rotExplicitContent: ByteArray): RootOfTrust? {
        val seq = Asn1Reader(rotExplicitContent)
        val seqTag = seq.readTag()
        if (seqTag.size != 1 || (seqTag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
        val seqLen = seq.readLength()
        val r = Asn1Reader(rotExplicitContent, seq.pos, seq.pos + seqLen)

        var index = 0
        var deviceLocked: Boolean? = null
        var verifiedBootState: Int? = null
        while (r.hasMore()) {
            val tag = r.readTag()
            val len = r.readLength()
            val contentStart = r.pos
            r.pos = contentStart + len
            val tagByte = if (tag.size == 1) tag[0].toInt() and 0xFF else -1
            when (index) {
                1 -> if (tagByte == TAG_BOOLEAN && len >= 1) {
                    deviceLocked = (r.buf[contentStart].toInt() and 0xFF) != 0
                }
                2 -> if (tagByte == TAG_ENUMERATED && len >= 1) {
                    verifiedBootState = r.buf[contentStart].toInt() and 0xFF
                }
            }
            index++
        }
        if (deviceLocked == null || verifiedBootState == null) return null
        return RootOfTrust(deviceLocked, verifiedBootState)
    }
}
