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
        } catch (_: Throwable) {
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

    /*
     * Google's status list keys serials as lowercase hex, no leading zeros.
     *
     * abs() because BigInteger.toString(16) renders a negative value with a
     * leading '-', which can never match an entry in the list. X.509 serials
     * are defined positive, but the value is parsed from a certificate an
     * attacker wrote, and a serial that silently fails every lookup would be a
     * free way to opt out of revocation.
     */
    fun normalizeSerial(serial: BigInteger): String = serial.abs().toString(16)

    /*
     * Every form a serial may take as a key in Google's status list.
     *
     * The list is NOT uniformly hex. Measured against the live list
     * (1742 entries, Last-Modified 2026-08-26): 768 keys are 30 to 32
     * characters and contain a-f, which is a 128-bit serial in hex, while 974
     * keys (55.9%) are 17 to 20 characters of pure digits. Those are decimal:
     * read as decimal every one of them lands inside unsigned 64 bits, and read
     * as hex every one of them overflows it. A 20-character hex serial
     * containing no a-f at all has probability 8.3e-05, and there are 438 of
     * them, so the digits are not a coincidence of hex encoding.
     *
     * Looking up the hex form only, as this did, therefore missed more than
     * half of every revoked keybox Google publishes. That matters more now than
     * it did: against a spoofer that runs a real KeyMint implementation and
     * re-signs with a genuine, Google-rooted keybox, the chain verifies, the
     * challenge echoes and the authorization tags are honest, so revocation is
     * the check left standing.
     *
     * Both forms are returned rather than guessing per-serial, since a lookup
     * is a set membership test and a wrong-encoding miss is silent. distinct()
     * because small serials render identically in both bases.
     */
    fun serialLookupKeys(serial: BigInteger): List<String> {
        val positive = serial.abs()
        return listOf(positive.toString(16), positive.toString(10)).distinct()
    }

    /*
     * 1a, applied to a real chain. Verifies every link with the platform's own
     * signature implementation.
     *
     * Split out of the probes so both the passive and the active one run
     * identical crypto, and so the actual verification is reachable from a JVM
     * unit test instead of only from a device.
     *
     * The exception mapping is the security-relevant part:
     *  - SignatureException / InvalidKeyException: the link is provably bad.
     *  - NoSuchAlgorithmException: the signature algorithm OID is written by
     *    whoever built the certificate. A leaf whose algorithm the platform
     *    cannot even name is not "a link we failed to check", it is a link that
     *    cannot have come from a real batch key, so it counts as broken. Left
     *    as inconclusive it was a free bypass: forge the leaf, set a nonsense
     *    algorithm OID, and the chain verifies.
     *  - anything else (no provider, encoding trouble): genuinely inconclusive,
     *    so the link is treated as valid and never manufactures a detection.
     */
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

    /*
     * Every certificate that ISSUES another one in the chain must be a CA.
     *
     * Without this, a signature-valid chain anchored at a genuine Google root
     * still proves nothing: an ordinary attested key generated on a real device
     * is an end-entity certificate whose private key lives in the attacker's
     * own Keystore and can sign arbitrary bytes, including a certificate. They
     * mint a forged leaf under it and present
     * [forged leaf, their real attested leaf, intermediate, Google root]. Every
     * link verifies and the chain anchors, so both the anchoring check and the
     * signature check pass while the forged leaf's attestation extension says
     * whatever they like. Standard PKIX rejects this on basicConstraints; this
     * is that check.
     *
     * Index 0 is the leaf and is expected NOT to be a CA, so it is skipped.
     * getBasicConstraints() returns -1 for a non-CA and the path-length
     * constraint otherwise. Any error yields false, never a detection.
     */
    fun chainHasNonCaIssuer(chain: List<X509Certificate>): Boolean {
        if (chain.size < 2) return false
        return try {
            (1 until chain.size).any { chain[it].basicConstraints < 0 }
        } catch (_: Throwable) {
            false
        }
    }

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
        } catch (_: Throwable) {
            false
        }
    }

    /*
     * Authentication self-contradiction.
     *
     * Call ONLY for a key that was requested with setUserAuthenticationRequired
     * (true). Real KeyMint then attests USER_AUTH_TYPE (504) and AUTH_TIMEOUT
     * (505) and omits NO_AUTH_REQUIRED (503) entirely. A spoofer that emits 503
     * unconditionally while modelling no authentication at all contradicts
     * itself, and requiring 503 present AND both 504/505 absent keeps that
     * fail-safe: a device that reports the authentication tags cannot trip it.
     *
     * COVERAGE, as of 2026-08-28: this now fires on nothing current, and is
     * retained only for the TEESimulator v3 line and older installs.
     * TrickyStoreOSS made the tag conditional in commit 2f15feb,
     * 2026-07-31T16:23:55Z, about sixteen hours after the v2.5 release:
     *     -        teeTag(503, DERNull.INSTANCE)
     *     +        if (params.noAuthRequired == true) teeTag(503, DERNull.INSTANCE)
     * Since the active probe asks for an auth-REQUIRED key, 503 is now absent
     * there and the predicate returns false. ForgeStore carries the same guard,
     * and TEESimulator v4 and OhMyKeymint emit the tag from a real KeyMint
     * implementation, so it is honest for them too.
     *
     * Recorded rather than quietly left in place: a check whose comment claims
     * coverage it no longer has is the same failure this project keeps hitting.
     * The active probe's remaining live signal against that family is
     * leafSignatureTracksRequestedDigest.
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
     *
     * Narrowed to SHA-512 only: that is the digest the active probe actually
     * requests, so it is the sole value whose presence proves the signer echoed
     * our request back. SHA-384 and SHA-1 proved nothing either way and
     * SHA-384 carried real false-positive risk, because Google's own
     * attestation PKI uses P-384 keys (the ECDSA root pinned in
     * AttestationRoots self-signs with ecdsa-with-SHA384), so a device whose
     * batch key is P-384 would sign leaves SHA384withECDSA on stock hardware.
     */
    fun leafSignatureTracksRequestedDigest(sigAlgName: String?): Boolean {
        if (sigAlgName.isNullOrBlank()) return false
        val normalized = sigAlgName.uppercase().replace("-", "")
        if (!normalized.contains("WITH")) return false
        return normalized.substringBefore("WITH") == "SHA512"
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
        } catch (_: Throwable) {
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
        } catch (_: Throwable) {
            null
        }
    }

    /*
     * KeyDescription field [1], attestationSecurityLevel: 0 Software,
     * 1 TrustedEnvironment, 2 StrongBox. Position-stable across every
     * attestation version, so positional access at index 1 is safe.
     *
     * Needed to tell "this chain is forged" apart from "this device has no
     * hardware attestation to forge". A Software-level chain is signed by the
     * public AOSP software attestation key, which is deliberately not pinned,
     * so anchoring fails for it on perfectly clean emulators, GSI images and
     * AOSP builds. Reporting that as an attestation anomaly contradicts the
     * probe's own rule that absence of attestation must never flag.
     *
     * Safe to trust for THIS purpose even though a spoofer writes the field:
     * declaring Software is declaring the key is not hardware-backed, which
     * fails the integrity verdict the spoofer exists to pass.
     *
     * Returns null on any structural surprise -> caller keeps its old behaviour.
     */
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
        } catch (_: Throwable) {
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
    private const val ATTESTATION_SECURITY_LEVEL_INDEX = 1

    /* attestationSecurityLevel values. */
    const val SECURITY_LEVEL_SOFTWARE = 0

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
                /*
                 * A high-tag-number form whose continuation bytes run to the end
                 * of this element leaves pos at end + 1. Without this guard the
                 * subsequent readLength() reads a byte belonging to the NEXT
                 * element (the backing array outlives `end`), silently
                 * mis-parsing instead of failing.
                 */
                if (pos > end) throw IllegalStateException("truncated tag")
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
            /*
             * Bounds math in Long, deliberately. The length field is chosen by
             * whoever built the certificate, so `pos + len` in Int overflows to
             * a negative number for a length near 0x7FFFFFFF and slips past both
             * clauses. copyOfRange is then handed (pos, negative), whose own
             * `to - from` underflows back to a positive 2 GB, so its range check
             * passes too and the allocation is attempted: OutOfMemoryError, an
             * Error rather than an Exception, unwinds past every `catch
             * (_: Exception)` here and is read by the probes as "no anomaly".
             */
            if (len < 0 || pos.toLong() + len.toLong() > end.toLong())
                throw IllegalStateException("length overflow")
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
     * Maximum nesting this search will follow. A real KeyDescription nests
     * about six deep (extension octet string -> KeyDescription -> Authorization
     * List -> [704] -> RootOfTrust -> field); 20 leaves generous headroom.
     *
     * The cap is a correctness requirement, not a tuning knob: nesting depth is
     * chosen by whoever built the certificate, and unbounded recursion on a
     * hostile extension raises StackOverflowError, an Error rather than an
     * Exception, which unwinds past every `catch (_: Exception)` here and is
     * read by the probes as "no anomaly".
     */
    private const val MAX_DER_DEPTH = 20

    /*
     * Depth-first search for the first TLV whose tag equals `target`; returns
     * that element's content bytes. Recurses into constructed elements.
     */
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
