package io.github.ir0nbyte.pifdetector

import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.X509Certificate

/*
 * Pure, framework-free decision + parsing logic for the key-attestation probe
 * (KeyAttestationProbe). Kept separate from the Keystore I/O so it can be
 * unit-tested on the JVM -- the live probe itself needs a real device and is
 * not unit-testable.
 *
 * Everything here is written to FAIL SAFE: any malformed / unexpected input
 * yields "no anomaly" (false / null) rather than a detection, so a parsing
 * gap can never produce a false positive. Only positively-proven invalid or
 * contradictory attestation flags.
 */
object AttestationAnalysis {

    /* Android key attestation extension OID. */
    const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    /* VerifiedBootState ENUMERATED values (Keymaster/KeyMint). */
    const val VERIFIED_BOOT_STATE_VERIFIED = 0

    /*
     * RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET_STRING, deviceLocked
     * BOOLEAN, verifiedBootState ENUMERATED, verifiedBootHash OCTET_STRING }
     * We only need the two boot-integrity fields.
     */
    data class RootOfTrust(val deviceLocked: Boolean, val verifiedBootState: Int)

    /*
     * 1a -- chain signature validation.
     *
     * Walks the chain leaf->root checking each cert is signed by its issuer.
     * The actual crypto is injected as `verifyLink(i)` == "is chain[i] signed
     * by chain[i+1]?" so this iteration/boundary logic is testable without
     * real certificates. Leaf-hacking spoof modes mutate the leaf's
     * attestation extension, breaking the issuer's signature over it.
     *
     * A chain with fewer than 2 certs cannot be cryptographically validated
     * (no issuer in hand) -> returns false (no flag), never a false positive.
     */
    fun chainIsCryptographicallyBroken(certCount: Int, verifyLink: (childIndex: Int) -> Boolean): Boolean {
        if (certCount < 2) return false
        for (i in 0 until certCount - 1) {
            if (!verifyLink(i)) return true
        }
        return false
    }

    /*
     * 1b -- attestation-vs-device contradiction.
     *
     * Spoofers force the attestation RootOfTrust to deviceLocked=true /
     * verifiedBootState=Verified. If attestation claims a locked/verified
     * device while the native engine's own signals already prove tampering
     * (bootloader unlocked, root hider, or Zygisk present), that contradiction
     * is a spoof. Null RootOfTrust (couldn't parse / not present) -> no flag.
     */
    fun isBootContradiction(rot: RootOfTrust?, deviceTampered: Boolean): Boolean {
        if (rot == null || !deviceTampered) return false
        val attestationClaimsClean =
            rot.deviceLocked || rot.verifiedBootState == VERIFIED_BOOT_STATE_VERIFIED
        return attestationClaimsClean
    }

    /*
     * Anti-replay: the attestation MUST echo the exact challenge nonce we
     * passed to setAttestationChallenge. A spoofer replaying a cached/precomputed
     * attestation cert won't carry our fresh nonce. Returns true only when a
     * challenge was parsed AND differs from what we sent -- a null/absent parse
     * yields false (fail safe), never a false positive.
     */
    fun challengeMismatch(parsedChallenge: ByteArray?, expected: ByteArray): Boolean {
        if (parsedChallenge == null) return false
        return !parsedChallenge.contentEquals(expected)
    }

    /*
     * 1c -- anchor the chain to a genuine Google attestation root. A real
     * hardware-attested chain terminates at one of Google's pinned roots; a
     * software/AOSP-software-keybox or fake-root spoof does not. Returns false
     * ONLY when we conclusively checked and no pinned root anchors the chain
     * (the flag condition). Every inconclusive case -- empty chain, no pinned
     * roots loaded, or any error -- returns true (fail safe, never flags).
     *
     * Handles both shapes Android may return: the root included in the chain
     * (SHA-256(DER) match on the top cert) and the root omitted (the top cert
     * is signed by a pinned root's public key).
     */
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
                    // top not signed by this root; try the next pinned root
                }
            }
            false
        } catch (_: Exception) {
            true
        }
    }

    /*
     * 1d -- revocation. Google's attestation status list holds only bad serials,
     * so presence => revoked/suspended keybox (the only way to catch
     * generation-mode spoofers whose chain is otherwise cryptographically valid
     * against a real Google root). Absence => good.
     */
    fun anyCertRevoked(chainSerials: List<String>, revokedSerials: Set<String>): Boolean {
        if (revokedSerials.isEmpty()) return false
        return chainSerials.any { revokedSerials.contains(it) }
    }

    /* Google's status list keys serials as lowercase hex, no leading zeros. */
    fun normalizeSerial(serial: BigInteger): String = serial.toString(16)

    // --- active-probe analysis (DETECTION_ATTEST_FORGERY) --------------------

    /*
     * AuthorizationList tags used by the active probe.
     *
     * A forged KeyDescription is BUILT rather than reported, so the builder has
     * to decide each tag's value without a TEE to ask. Both known keybox
     * spoofers emit NO_AUTH_REQUIRED unconditionally and emit none of the
     * authentication tags at all, because they never model authentication.
     */
    const val TAG_NO_AUTH_REQUIRED = 503
    const val TAG_USER_AUTH_TYPE = 504
    const val TAG_AUTH_TIMEOUT = 505

    /*
     * DER identifier octets for a context-class CONSTRUCTED tag, as used for
     * every EXPLICIT entry in an AuthorizationList. Low tag numbers (<31) use
     * the short form (0xA0 | n); anything larger uses the high-tag-number form
     * (0xBF followed by base-128, high bit set on all but the final byte).
     * Tag 704 encodes to BF 85 40, matching ROOT_OF_TRUST_TAG above.
     */
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

    /*
     * True when the hardwareEnforced AuthorizationList carries `tagNo`.
     *
     * Scoped to the hardwareEnforced list (the last KeyDescription field) for
     * the same reason parseRootOfTrust is: a value inside softwareEnforced, or
     * a byte run that merely looks like the tag, must not be mistaken for a
     * TEE-enforced entry. Any structural surprise yields false.
     */
    fun hasHardwareEnforcedTag(extensionValue: ByteArray, tagNo: Int): Boolean {
        return try {
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return false
            val hardwareEnforced = lastSequenceChildContent(unwrapped) ?: return false
            findTaggedContent(hardwareEnforced, contextConstructedTag(tagNo)) != null
        } catch (_: Exception) {
            false
        }
    }

    /*
     * Authentication self-contradiction.
     *
     * Call ONLY for a key that was requested with setUserAuthenticationRequired
     * (true). Real KeyMint then attests USER_AUTH_TYPE (504) and AUTH_TIMEOUT
     * (505) and omits NO_AUTH_REQUIRED (503) entirely. Both known spoofers emit
     * `teeTag(503, DERNull.INSTANCE)` with no surrounding condition -- note that
     * in the same builder the patch-level tags ARE guarded, so this is not a
     * generic "everything is unconditional" artifact -- and emit neither 504 nor
     * 505, because nothing in the forged path models authentication.
     *
     * Requiring 503 present AND both 504/505 absent keeps this fail-safe: a
     * device that reports the authentication tags cannot trip it, whatever else
     * it does with 503.
     */
    fun authRequirementContradiction(extensionValue: ByteArray): Boolean {
        val claimsNoAuth = hasHardwareEnforcedTag(extensionValue, TAG_NO_AUTH_REQUIRED)
        if (!claimsNoAuth) return false
        val hasAuthType = hasHardwareEnforcedTag(extensionValue, TAG_USER_AUTH_TYPE)
        val hasAuthTimeout = hasHardwareEnforcedTag(extensionValue, TAG_AUTH_TIMEOUT)
        return !hasAuthType && !hasAuthTimeout
    }

    /*
     * Leaf signature-algorithm anomaly.
     *
     * A device's attestation batch key is provisioned once and signs every leaf
     * with a fixed algorithm, always SHA-256 based. One spoofer instead builds
     * its signer as "${requestedDigest}with${keyboxAlgorithm}", so the digest we
     * asked for on the ATTESTED key leaks into the signature over the leaf. We
     * request SHA-512, so a SHA-512-signed leaf means the signer tracked our
     * request, which no real TEE does.
     *
     * Only a positively recognised non-SHA-256 digest flags; an unparseable or
     * unfamiliar algorithm name yields false.
     */
    fun leafSignatureTracksRequestedDigest(sigAlgName: String?): Boolean {
        if (sigAlgName.isNullOrBlank()) return false
        val normalized = sigAlgName.uppercase().replace("-", "")
        if (!normalized.contains("WITH")) return false
        val digest = normalized.substringBefore("WITH")
        return digest == "SHA512" || digest == "SHA384" || digest == "SHA1"
    }

    /*
     * A single self-signed certificate that nonetheless carries an attestation
     * extension. Real hardware attestation always returns a chain terminating at
     * a Google CA, so length 1 with issuer == subject is one spoofer's
     * documented fallback path and cannot occur genuinely. Returns false for any
     * chain of length != 1 so ordinary chains are untouched.
     */
    fun isSelfSignedSingleCert(chain: List<X509Certificate>): Boolean {
        if (chain.size != 1) return false
        return try {
            val cert = chain[0]
            cert.getExtensionValue(ATTESTATION_OID) != null &&
                cert.issuerX500Principal == cert.subjectX500Principal
        } catch (_: Exception) {
            false
        }
    }

    /*
     * Pull the attestationChallenge (KeyDescription field index 4, OCTET STRING)
     * out of the extension. The first six KeyDescription fields are position-
     * stable across Keymaster/KeyMint, so positional access at index 4 is safe.
     * Returns null on any structural surprise -> fail safe.
     */
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
        } catch (_: Exception) {
            null
        }
    }

    /*
     * Parse deviceLocked + verifiedBootState out of a key-attestation extension
     * value (the raw bytes from X509Certificate.getExtensionValue, i.e. an
     * OCTET STRING wrapping the KeyDescription SEQUENCE).
     *
     * Rather than walk KeyDescription by fixed field index (which shifts
     * between Keymaster and KeyMint schemas), we DFS for the RootOfTrust tag
     * [704] EXPLICIT and parse the SEQUENCE inside it. Returns null on any
     * structural surprise -> fail safe.
     */
    fun parseRootOfTrust(extensionValue: ByteArray): RootOfTrust? {
        return try {
            // getExtensionValue() returns an OCTET STRING wrapping the real value.
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return null
            // RootOfTrust is defined only in the hardwareEnforced AuthorizationList
            // (the last KeyDescription field). Scoping the [704] DFS to that field
            // prevents a stray / forged [704] inside softwareEnforced -- or a byte
            // run that merely looks like the BF 85 40 tag -- from misleading us.
            val hardwareEnforced = lastSequenceChildContent(unwrapped) ?: return null
            val rotContent = findTaggedContent(hardwareEnforced, ROOT_OF_TRUST_TAG) ?: return null
            parseRootOfTrustSequence(rotContent)
        } catch (_: Exception) {
            null
        }
    }

    // --- minimal DER reader (private) ---------------------------------------

    /* [704] EXPLICIT, context-class + constructed: 0xBF 0x85 0x40. */
    private val ROOT_OF_TRUST_TAG = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40.toByte())

    private const val TAG_BOOLEAN = 0x01
    private const val TAG_OCTET_STRING = 0x04
    private const val TAG_ENUMERATED = 0x0A
    private const val TAG_SEQUENCE = 0x30

    /* KeyDescription field order: [0]version [1]secLevel [2]kmVersion
     * [3]kmSecLevel [4]attestationChallenge [5]uniqueId [6]swEnforced
     * [7]hwEnforced. The leading fields are position-stable across versions. */
    private const val ATTESTATION_CHALLENGE_INDEX = 4

    private class Asn1Reader(val buf: ByteArray, var pos: Int = 0, val end: Int = buf.size) {
        fun hasMore(): Boolean = pos < end

        /* Reads a tag (handles high-tag-number form), returns its raw bytes. */
        fun readTag(): ByteArray {
            val start = pos
            val first = buf[pos++].toInt() and 0xFF
            if (first and 0x1F == 0x1F) {
                // high-tag-number form: subsequent bytes while high bit set
                while (pos < end && (buf[pos].toInt() and 0x80) != 0) pos++
                pos++ // final byte with high bit clear
            }
            return buf.copyOfRange(start, pos)
        }

        fun isConstructed(tag: ByteArray): Boolean = (tag[0].toInt() and 0x20) != 0

        /* Reads a definite-length (short or long form). */
        fun readLength(): Int {
            var len = buf[pos++].toInt() and 0xFF
            if (len and 0x80 != 0) {
                val numBytes = len and 0x7F
                if (numBytes == 0 || numBytes > 4) throw IllegalStateException("bad length")
                len = 0
                repeat(numBytes) { len = (len shl 8) or (buf[pos++].toInt() and 0xFF) }
            }
            if (len < 0 || pos + len > end) throw IllegalStateException("length overflow")
            return len
        }
    }

    /*
     * Given a SEQUENCE TLV, return the content bytes of its LAST child element.
     * Used to isolate the hardwareEnforced AuthorizationList (the final
     * KeyDescription field) before searching it for RootOfTrust.
     */
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

    /* If `data` begins with a single OCTET STRING TLV, return its content. */
    private fun readSingleOctetStringContent(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null
        val r = Asn1Reader(data)
        val tag = r.readTag()
        if (tag.size != 1 || (tag[0].toInt() and 0xFF) != TAG_OCTET_STRING) return null
        val len = r.readLength()
        return data.copyOfRange(r.pos, r.pos + len)
    }

    /*
     * Depth-first search for the first TLV whose tag equals `target`; returns
     * that element's content bytes. Recurses into constructed elements.
     */
    private fun findTaggedContent(data: ByteArray, target: ByteArray): ByteArray? {
        val r = Asn1Reader(data)
        while (r.hasMore()) {
            val tag = r.readTag()
            val len = r.readLength()
            val contentStart = r.pos
            val content = data.copyOfRange(contentStart, contentStart + len)
            r.pos = contentStart + len

            if (tag.contentEquals(target)) return content
            if (r.isConstructed(tag)) {
                val nested = findTaggedContent(content, target)
                if (nested != null) return nested
            }
        }
        return null
    }

    /* Parse a RootOfTrust SEQUENCE content: [0] octet, [1] BOOLEAN, [2] ENUM. */
    private fun parseRootOfTrustSequence(rotExplicitContent: ByteArray): RootOfTrust? {
        // [704] EXPLICIT wraps a SEQUENCE; unwrap that SEQUENCE first.
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
