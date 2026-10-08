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

    /**
     * The distinct public keys of a pinned set, as encoded SubjectPublicKeyInfo.
     *
     * Google re-issues one attestation key as several certificates, so the
     * question a trust gate actually wants answered is whether a certificate
     * carries an anchor's KEY, not whether it matches an anchor's bytes.
     * Deriving it in one place stops the gates drifting apart, which they had:
     * the validity gate compared keys while the revocation gate compared
     * encodings, so a handset serving a re-issued root had the root's own
     * serial submitted for revocation lookup.
     */
    fun anchorKeyEncodings(pinnedRoots: List<X509Certificate>): Set<List<Byte>> =
        pinnedRoots.mapNotNullTo(HashSet()) { root ->
            runCatching { root.publicKey?.encoded?.toList() }.getOrNull()
        }

    /** Whether this certificate's public key is one of [anchorKeys]. */
    fun carriesAnchorKey(cert: X509Certificate, anchorKeys: Set<List<Byte>>): Boolean {
        if (anchorKeys.isEmpty()) return false
        val key = runCatching { cert.publicKey?.encoded?.toList() }.getOrNull() ?: return false
        return key in anchorKeys
    }

    /**
     * Whether this certificate IS an instance of a trust anchor, rather than
     * merely carrying an anchor's key.
     *
     * Carrying the key is not sufficient, and the difference is reachable.
     * Anyone holding a leaked keybox can mint a leaf whose SubjectPublicKeyInfo
     * is a Google root's public key and have the batch key sign it; that chain
     * still verifies link by link and still anchors. Keying a skip on the
     * public key alone would let such a leaf exclude itself from whatever the
     * skip protects. Every published root is self-signed, so requiring that too
     * describes a root instance exactly and leaves the forgery outside it.
     *
     * The cost of the stricter rule is a cross-signed root, which Google does
     * not currently publish, being treated as an ordinary certificate. That
     * direction is the safe one.
     */
    fun isAnchorInstance(cert: X509Certificate, anchorKeys: Set<List<Byte>>): Boolean {
        if (!carriesAnchorKey(cert, anchorKeys)) return false
        return runCatching {
            cert.issuerX500Principal == cert.subjectX500Principal
        }.getOrDefault(false)
    }

    /**
     * Pinning four certificates over one key does not make this loop redundant
     * work: it returns on the first root that answers, so an anchored chain
     * costs one digest and one verification whichever instance it presents.
     * Collapsing the repeated key up front was measured and was slower, because
     * it encodes every anchor key before verifying any of them.
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

    /**
     * A serial is looked up in both encodings because the published list mixes
     * them. Renderings shorter than the list's own minimum are dropped: a
     * one-character key could otherwise match a genuine certificate.
     */
    fun serialLookupKeys(serial: BigInteger): List<String> {
        val positive = serial.abs()
        return listOf(positive.toString(16), positive.toString(10))
            .filter { it.length >= MIN_SERIAL_KEY_LENGTH }
            .distinct()
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
            val hardwareEnforced = hardwareEnforcedList(extensionValue) ?: return false
            findTopLevelTaggedContent(hardwareEnforced, contextConstructedTag(tagNo)) != null
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * The hardwareEnforced AuthorizationList, which is KeyDescription child 7.
     *
     * Addressed by index rather than "the last child", because an adversary who
     * appends an extra element to the SEQUENCE would otherwise redirect every
     * lookup into a list they fully control while a strict verifier still reads
     * the real one.
     */
    private fun hardwareEnforcedList(extensionValue: ByteArray): ByteArray? =
        authorizationList(extensionValue, HARDWARE_ENFORCED_INDEX)

    private fun authorizationList(extensionValue: ByteArray, listIndex: Int): ByteArray? {
        val unwrapped = readSingleOctetStringContent(extensionValue) ?: return null
        val r = Asn1Reader(unwrapped)
        val seqTag = r.readTag()
        if (seqTag.size != 1 || (seqTag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
        val seqLen = r.readLength()
        val inner = Asn1Reader(unwrapped, r.pos, r.pos + seqLen)

        var index = 0
        var found: ByteArray? = null
        while (inner.hasMore()) {
            inner.readTag()
            val len = inner.readLength()
            val start = inner.pos
            inner.pos = start + len
            if (index == listIndex) {
                found = unwrapped.copyOfRange(start, start + len)
            }
            index++
        }
        // KeyDescription has exactly eight members. A different count is a
        // hand-built record, not something a KeyMint implementation emits.
        if (index != KEY_DESCRIPTION_CHILDREN) return null
        return found
    }

    /**
     * Scans only the immediate members of an authorization list.
     *
     * [findTaggedContent] recurses and returns the first depth-first match, so a
     * decoy copy of a tag buried inside an earlier constructed member would
     * shadow the real top-level entry. A duplicate at this level is itself
     * evidence of a hand-built record, so it returns null rather than guessing.
     */
    private fun findTopLevelTaggedContent(data: ByteArray, target: ByteArray): ByteArray? {
        val r = Asn1Reader(data)
        var found: ByteArray? = null
        while (r.hasMore()) {
            val tag = r.readTag()
            val len = r.readLength()
            val start = r.pos
            r.pos = start + len
            if (tag.contentEquals(target)) {
                if (found != null) return null
                found = data.copyOfRange(start, start + len)
            }
        }
        return found
    }

    fun authRequirementContradiction(extensionValue: ByteArray): Boolean {
        val claimsNoAuth = hasHardwareEnforcedTag(extensionValue, TAG_NO_AUTH_REQUIRED)
        if (!claimsNoAuth) return false
        val hasAuthType = hasHardwareEnforcedTag(extensionValue, TAG_USER_AUTH_TYPE)
        val hasAuthTimeout = hasHardwareEnforcedTag(extensionValue, TAG_AUTH_TIMEOUT)
        return !hasAuthType && !hasAuthTimeout
    }

    const val TAG_OS_PATCH_LEVEL = 706
    const val TAG_VENDOR_PATCH_LEVEL = 718
    const val TAG_BOOT_PATCH_LEVEL = 719

    /** moduleHash, KeyMint 4.0. AOSP and CTS place it in the software-enforced list. */
    const val TAG_MODULE_HASH = 724

    /** Properties read from the device itself, for comparison against attestation. */
    data class DeviceFacts(
        val systemSecurityPatch: String?,
        val vendorSecurityPatch: String?,
        val vbmetaDigestHex: String?,
        val vbmetaHashAlg: String?,
    ) {
        companion object {
            val EMPTY = DeviceFacts(null, null, null, null)
        }
    }

    data class CrossSourceVerdict(
        val osPatchAhead: Boolean,
        val vendorPatchAhead: Boolean,
        val bootHashMismatch: Boolean,
        val osPatchDisagrees: Boolean = false,
        val vendorPatchCopiedFromSystemProperty: Boolean = false,
        val malformedDayPrecisionPatchLevel: Boolean = false,
        val bootPatchLevelMissing: Boolean = false,
        val attestedBootHashUnusable: Boolean = false,
        val monthPrecisionDayLevel: Boolean = false,
        val attestedBootPatchLevel: Long? = null,
        val attestedVendorPatchLevel: Long? = null,
        /** False when there was no hardware-backed, Google-anchored chain to compare. */
        val evaluated: Boolean = true,
    ) {
        /**
         * Four arms drive the verdict: the OS patch level being newer than the
         * property, the two levels disagreeing behind the strict gate, the boot
         * hash differing when both sides are real digests, and a day-00 patch
         * level. Five arms deliberately do not: the two vendor arms, the absent boot patch
         * level, a month-precision day field, and an attested boot hash that
         * carries no usable digest.
         *
         * The two VENDOR arms cannot evaluate on a normal install:
         * ro.vendor.build.security_patch is vendor_security_patch_level_prop,
         * which system/sepolicy grants to vendor_init, keystore and shell only,
         * while ro.build.version.security_patch is build_prop and readable by
         * every domain. A finding must never depend on a value only a
         * privileged process can read, so the vendor comparisons are computed
         * for the readout and excluded here.
         *
         * bootPatchLevelMissing is excluded because no test target available to
         * this project can validate it positively: VTS requires tag 719 by
         * default, but --skip_boot_pl_check exists, the one genuine device has
         * the tag, and both emulators are excluded at the gate.
         *
         * monthPrecisionDayLevel is excluded because an OEM TA that tracks the
         * vendor or boot partition at month granularity is sloppy, not a
         * spoofer. Only a value that is neither a valid YYYYMMDD nor a valid
         * YYYYMM reaches malformedDayPrecisionPatchLevel.
         *
         * The boot-hash arm does drive the verdict. VTS verify_root_of_trust
         * asserts the attested hash equals ro.boot.vbmeta.digest whenever AVB
         * verification is enabled, and the arm only evaluates when the device's
         * own digest is usable and the algorithm really is sha256.
         */
        val anyMismatch: Boolean get() =
            osPatchAhead || osPatchDisagrees || bootHashMismatch ||
                malformedDayPrecisionPatchLevel

        companion object {
            val NONE = CrossSourceVerdict(false, false, false)

            /**
             * No chain worth comparing. Not a pass: the row reads as not
             * observable on this device, which keeps it out of the review count.
             */
            val NOT_EVALUATED = CrossSourceVerdict(false, false, false, evaluated = false)
        }
    }

    /**
     * Reads a hardware-enforced INTEGER tag from the authorization list. The
     * EXPLICIT tag's content is a whole INTEGER TLV, so one TLV is read from it.
     */
    /**
     * The tag numbers of an authorization list, in the order the record emits
     * them. Null when the list cannot be read, or when any child is not a
     * canonically encoded context-specific constructed tag, because a verdict
     * about shape must not be drawn from bytes that did not parse cleanly.
     */
    fun authorizationListTags(extensionValue: ByteArray, listIndex: Int): List<Int>? {
        return try {
            val list = authorizationList(extensionValue, listIndex) ?: return null
            val r = Asn1Reader(list)
            val tags = ArrayList<Int>()
            while (r.hasMore()) {
                val tag = r.readTag()
                val len = r.readLength()
                r.pos += len
                val n = decodeContextConstructedTag(tag) ?: return null
                tags.add(n)
            }
            tags
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * An OCTET STRING tag from the software-enforced list. Goes through the
     * same eight-member KeyDescription guard as the hardware-enforced path, so
     * a record with a different member count yields nothing.
     */
    fun parseSoftwareEnforcedOctetString(extensionValue: ByteArray, tagNo: Int): ByteArray? {
        return try {
            val list = authorizationList(extensionValue, SOFTWARE_ENFORCED_INDEX) ?: return null
            val content = findTopLevelTaggedContent(list, contextConstructedTag(tagNo))
                ?: return null
            val r = Asn1Reader(content)
            val tag = r.readTag()
            if (tag.size != 1 || (tag[0].toInt() and 0xFF) != TAG_OCTET_STRING) return null
            val len = r.readLength()
            if (r.pos + len > content.size) return null
            content.copyOfRange(r.pos, r.pos + len)
        } catch (_: Throwable) {
            null
        }
    }

    fun parseAttestedModuleHash(extensionValue: ByteArray): ByteArray? =
        parseSoftwareEnforcedOctetString(extensionValue, TAG_MODULE_HASH)

    fun hardwareEnforcedTags(extensionValue: ByteArray): List<Int>? =
        authorizationListTags(extensionValue, HARDWARE_ENFORCED_INDEX)

    fun softwareEnforcedTags(extensionValue: ByteArray): List<Int>? =
        authorizationListTags(extensionValue, SOFTWARE_ENFORCED_INDEX)

    /**
     * The inverse of contextConstructedTag. Rejects a non-minimal encoding: a
     * leading continuation byte of zero, or the high-tag-number form used for a
     * number the low form can carry. Either is a hand-built encoding.
     */
    internal fun decodeContextConstructedTag(tag: ByteArray): Int? {
        if (tag.isEmpty()) return null
        val first = tag[0].toInt() and 0xFF
        if (first and 0xE0 != 0xA0) return null
        if (first and 0x1F != 0x1F) {
            return if (tag.size == 1) first and 0x1F else null
        }
        if (tag.size < 2 || tag.size > 5) return null
        if ((tag[1].toInt() and 0x7F) == 0) return null
        var v = 0
        for (i in 1 until tag.size) {
            val b = tag[i].toInt() and 0xFF
            v = (v shl 7) or (b and 0x7F)
            val last = i == tag.size - 1
            if (last != ((b and 0x80) == 0)) return null
        }
        if (v < 0x1F) return null
        return v
    }

    fun parseHardwareEnforcedInteger(extensionValue: ByteArray, tagNo: Int): Long? {
        return try {
            val hardwareEnforced = hardwareEnforcedList(extensionValue) ?: return null
            val content = findTopLevelTaggedContent(hardwareEnforced, contextConstructedTag(tagNo))
                ?: return null

            val r = Asn1Reader(content)
            val tag = r.readTag()
            if (tag.size != 1 || (tag[0].toInt() and 0xFF) != TAG_INTEGER) return null
            val len = r.readLength()
            if (len < 1 || len > 8) return null
            // A negative value is not a valid patch level; reject rather than wrap.
            if ((content[r.pos].toInt() and 0x80) != 0) return null

            var value = 0L
            for (i in 0 until len) {
                value = (value shl 8) or (content[r.pos + i].toLong() and 0xFF)
            }
            value
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * The fourth RootOfTrust field, present from KeyMint v3. Deliberately not a
     * member of [RootOfTrust]: that is a data class, and a ByteArray member
     * would make its generated equals reference-based.
     */
    fun parseVerifiedBootHash(extensionValue: ByteArray): ByteArray? {
        return try {
            val hardwareEnforced = hardwareEnforcedList(extensionValue) ?: return null
            val rotContent = findTopLevelTaggedContent(hardwareEnforced, ROOT_OF_TRUST_TAG)
                ?: return null

            val seq = Asn1Reader(rotContent)
            val seqTag = seq.readTag()
            if (seqTag.size != 1 || (seqTag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
            val seqLen = seq.readLength()
            val r = Asn1Reader(rotContent, seq.pos, seq.pos + seqLen)

            var index = 0
            while (r.hasMore()) {
                val tag = r.readTag()
                val len = r.readLength()
                val start = r.pos
                r.pos = start + len
                if (index == ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX) {
                    val tagByte = if (tag.size == 1) tag[0].toInt() and 0xFF else -1
                    return if (tagByte == TAG_OCTET_STRING) {
                        rotContent.copyOfRange(start, start + len)
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

    /** Null means unknown, which never flags. */
    fun normalizeAttestedPatchToYearMonth(raw: Long?): Int? {
        if (raw == null) return null
        val yearMonth = when (raw) {
            in 200801L..209912L -> raw.toInt()
            in 20080101L..20991231L -> (raw / 100).toInt()
            else -> return null
        }
        val month = yearMonth % 100
        if (month !in 1..12) return null
        return yearMonth
    }

    /** Accepts 2024-12-05, 2024-12, 20241205 and 202412 identically. */
    fun normalizePropertyPatchToYearMonth(value: String?): Int? {
        if (value.isNullOrBlank()) return null
        val digits = value.filter { it.isDigit() }
        val raw = digits.toLongOrNull() ?: return null
        if (digits.length != 6 && digits.length != 8) return null
        return normalizeAttestedPatchToYearMonth(raw)
    }

    /**
     * Only an attested level NEWER than the device's own property is evidence.
     * The other direction is a legitimate lag and must never flag.
     */
    fun attestedPatchIsAheadOfProperty(attested: Int?, fromProperty: Int?): Boolean {
        if (attested == null || fromProperty == null) return false
        return attested > fromProperty
    }

    /**
     * Tags 718 and 719 are specified as YYYYMMDD. Null means the value is not a
     * valid calendar date, which is itself a signal; the caller decides.
     *
     * normalizeAttestedPatchToYearMonth is deliberately NOT tightened to reject
     * an 8-digit osPatchLevel: it accepts both forms today, no observed emitter
     * produces an 8-digit tag 706, and changing it would ripple into the
     * existing ahead-only arm and its tests.
     */
    fun normalizeAttestedPatchToYearMonthDay(raw: Long?): Int? {
        if (raw == null) return null
        if (raw < 20080101L || raw > 20991231L) return null
        val v = raw.toInt()
        val month = (v / 100) % 100
        val day = v % 100
        if (month !in 1..12) return null
        if (day !in 1..31) return null
        return v
    }

    /**
     * Mirrors AOSP's own property regex, ^([0-9]{4})-([0-9]{2})-([0-9]{2})$,
     * from keymaster_configuration.cpp. Anything the HAL would have parsed as 0
     * must come back null here, or we would compare a value we invented against
     * a value the HAL never had. Do not reuse the lenient year-month parser for
     * the day-precision arms.
     */
    fun normalizePropertyPatchToYearMonthDay(value: String?): Int? {
        if (value == null || value.length != 10) return null
        if (value[4] != '-' || value[7] != '-') return null
        for (i in intArrayOf(0, 1, 2, 3, 5, 6, 8, 9)) if (!value[i].isDigit()) return null
        val raw = (value.substring(0, 4) + value.substring(5, 7) + value.substring(8, 10))
            .toLongOrNull() ?: return null
        return normalizeAttestedPatchToYearMonthDay(raw)
    }

    /**
     * Narrow on purpose: an 8-digit value carrying a real year and a real month
     * but a day of 00, and nothing else.
     *
     * That exact shape has a named emitter on the bypass side, where a
     * month-granular config value is multiplied out to the long form, and
     * AOSP's own GetPatchlevel cannot produce it because its regex requires a
     * two-digit day drawn from a real date.
     *
     * Every other non-date shape is forgiven and reported instead: a bare
     * YYYYMM, a zero-padded year like 20250000, and anything else unparseable.
     * An OEM that tracks a partition at coarser than day granularity is
     * non-conforming rather than dishonest, and no measurement was available to
     * show which forms genuine vendors emit.
     */
    fun dayPrecisionPatchIsImpossible(raw: Long?): Boolean {
        if (raw == null || raw <= 0L) return false
        if (normalizeAttestedPatchToYearMonthDay(raw) != null) return false
        if (raw !in 20080000L..20991299L) return false
        val v = raw.toInt()
        val month = (v / 100) % 100
        val day = v % 100
        return month in 1..12 && day == 0
    }

    /**
     * A day-precision tag carrying something coarser than a day: a bare YYYYMM,
     * or an 8-digit form that is not a date and is not the day-00 shape above.
     * Reported, never a finding.
     */
    fun dayPrecisionPatchIsMonthOnly(raw: Long?): Boolean {
        if (raw == null || raw <= 0L) return false
        if (normalizeAttestedPatchToYearMonthDay(raw) != null) return false
        return !dayPrecisionPatchIsImpossible(raw)
    }

    /**
     * Equality is what VTS asserts, so either direction of inequality is a
     * finding. Only safe behind a locked-and-verified gate: see the note on
     * strictPatchEquality in KeyAttestationProbe.
     */
    fun patchLevelsDisagree(attested: Int?, fromProperty: Int?): Boolean {
        if (attested == null || fromProperty == null) return false
        return attested != fromProperty
    }


    private fun usablePropertyDigest(
        propertyDigestHex: String?,
        propertyHashAlg: String?,
    ): ByteArray? {
        if (!"sha256".equals(propertyHashAlg?.trim(), ignoreCase = true)) return null
        val hex = propertyDigestHex?.trim() ?: return null
        if (hex.length != SHA256_BYTES * 2) return null
        if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        val decoded = ByteArray(SHA256_BYTES) { i ->
            ((Character.digit(hex[i * 2], 16) shl 4) or
                Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        // An all-zero property means the DEVICE has no digest, which is no
        // evidence about the record.
        if (decoded.all { it.toInt() == 0 }) return null
        return decoded
    }

    /**
     * A finding only when BOTH sides are real 32-byte digests and they differ.
     *
     * An earlier revision treated an all-zero or odd-length attested hash as a
     * contradiction, on the reasoning that ro.boot.vbmeta.digest is readable by
     * every SELinux domain so a conforming implementation has no excuse. That
     * overreached: all-zero is what AOSP emits when the implementation could
     * not read the property for any reason, and an unexpected length is an
     * encoding this code does not know. Neither is evidence about the device,
     * and no measurement was available to show a genuine device cannot produce
     * them. Both are reported through attestedBootHashUnusable and
     * the row detail instead.
     *
     * The equality itself is sound: VTS verify_root_of_trust asserts it
     * whenever AVB verification is enabled, and it holds exactly on all three
     * measured devices across three vendors.
     */
    fun verifiedBootHashMismatch(
        attestedHash: ByteArray?,
        propertyDigestHex: String?,
        propertyHashAlg: String?,
    ): Boolean {
        return try {
            val decoded = usablePropertyDigest(propertyDigestHex, propertyHashAlg) ?: return false
            if (attestedHash == null) return false
            if (attestedHash.size != SHA256_BYTES) return false
            if (attestedHash.all { it.toInt() == 0 }) return false
            !attestedHash.contentEquals(decoded)
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * The attested hash is present but carries no usable digest: all zeroes, or
     * not 32 bytes long. That is what an implementation emits when it could not
     * read the device's own digest.
     *
     * Deliberately says nothing about the property side. An earlier name
     * claimed both sources were absent, which the body never checked and which
     * is false whenever the device's own digest is perfectly readable.
     */
    fun attestedBootHashUnusable(attestedHash: ByteArray?): Boolean {
        if (attestedHash == null) return false
        return attestedHash.size != SHA256_BYTES || attestedHash.all { it.toInt() == 0 }
    }

    /**
     * A KeyMint simulator keeps the attestation record internally consistent,
     * but it does not control the device's own properties at the same time.
     */
    fun crossSourceMismatch(
        extensionValue: ByteArray,
        facts: DeviceFacts,
        strictPatchEquality: Boolean = false,
    ): CrossSourceVerdict {
        return try {
            val osRaw = parseHardwareEnforcedInteger(extensionValue, TAG_OS_PATCH_LEVEL)
            val vendorRaw = parseHardwareEnforcedInteger(extensionValue, TAG_VENDOR_PATCH_LEVEL)
            val bootRaw = parseHardwareEnforcedInteger(extensionValue, TAG_BOOT_PATCH_LEVEL)

            val osYm = normalizeAttestedPatchToYearMonth(osRaw)
            val sysPropYm = normalizePropertyPatchToYearMonth(facts.systemSecurityPatch)
            val venPropYm = normalizePropertyPatchToYearMonth(facts.vendorSecurityPatch)
            val sysPropYmd = normalizePropertyPatchToYearMonthDay(facts.systemSecurityPatch)
            val venPropYmd = normalizePropertyPatchToYearMonthDay(facts.vendorSecurityPatch)
            val vendorYmd = normalizeAttestedPatchToYearMonthDay(vendorRaw)
            val attVer = parseAttestationVersion(extensionValue)
            val attHash = parseVerifiedBootHash(extensionValue)

            // The older direction additionally requires Keymaster 4.0 or later.
            // On Keymaster 2 and 3 the TA receives os_patchlevel from the
            // bootloader via SetBootParams rather than from the HAL's
            // Configure() call, so a boot image left at an older level than the
            // system partition makes a genuine, locked, green device read as
            // behind. Those devices are inside minSdk 24 and anchor to the same
            // pinned root, so strictPatchEquality alone does not exclude them.
            val configureSourcedPatchLevel = attVer != null && attVer >= ATTESTATION_VERSION_KEYMASTER_4

            CrossSourceVerdict(
                // Ungated on purpose. CTS forbids an attested level NEWER than
                // the property in every configuration, including the GSI
                // carve-out, which relaxes only the other direction.
                osPatchAhead = attestedPatchIsAheadOfProperty(osYm, sysPropYm),
                vendorPatchAhead = attestedPatchIsAheadOfProperty(
                    normalizeAttestedPatchToYearMonth(vendorRaw), venPropYm
                ),
                // Gated like the OS equality arm. The VTS assertion behind this
                // comparison holds where AVB verification is enabled, so a
                // device whose own record says it is not verified is not a
                // device this arm can speak about.
                bootHashMismatch = strictPatchEquality && verifiedBootHashMismatch(
                    attHash, facts.vbmetaDigestHex, facts.vbmetaHashAlg
                ),
                osPatchDisagrees = strictPatchEquality && configureSourcedPatchLevel &&
                    patchLevelsDisagree(osYm, sysPropYm),
                vendorPatchCopiedFromSystemProperty =
                    sysPropYmd != null && venPropYmd != null && sysPropYmd != venPropYmd &&
                        vendorYmd != null && vendorYmd == sysPropYmd,
                malformedDayPrecisionPatchLevel =
                    dayPrecisionPatchIsImpossible(vendorRaw) ||
                        dayPrecisionPatchIsImpossible(bootRaw),
                monthPrecisionDayLevel =
                    dayPrecisionPatchIsMonthOnly(vendorRaw) ||
                        dayPrecisionPatchIsMonthOnly(bootRaw),
                bootPatchLevelMissing =
                    attVer != null && attVer >= ATTESTATION_VERSION_KEYMINT_3 &&
                        vendorRaw != null && bootRaw == null,
                attestedBootHashUnusable = attestedBootHashUnusable(attHash),
                attestedBootPatchLevel = bootRaw,
                attestedVendorPatchLevel = vendorRaw,
            )
        } catch (_: Throwable) {
            CrossSourceVerdict.NONE
        }
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

    /**
     * The nth immediate child of KeyDescription, as (singleByteTag, content).
     *
     * Deliberately does NOT enforce the member count. hardwareEnforcedList does,
     * because addressing the last child is what a crafted record can shift; the
     * two parsers below address a fixed low index, where an appended member
     * cannot move the field they want.
     */
    private fun keyDescriptionChild(extensionValue: ByteArray, index: Int): Pair<Int, ByteArray>? {
        return try {
            val unwrapped = readSingleOctetStringContent(extensionValue) ?: return null
            val r = Asn1Reader(unwrapped)
            val seqTag = r.readTag()
            if (seqTag.size != 1 || (seqTag[0].toInt() and 0xFF) != TAG_SEQUENCE) return null
            val seqLen = r.readLength()
            val inner = Asn1Reader(unwrapped, r.pos, r.pos + seqLen)
            var i = 0
            while (inner.hasMore()) {
                val tag = inner.readTag()
                val len = inner.readLength()
                val start = inner.pos
                inner.pos = start + len
                if (i == index) {
                    val tagByte = if (tag.size == 1) tag[0].toInt() and 0xFF else -1
                    return tagByte to unwrapped.copyOfRange(start, start + len)
                }
                i++
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * KeyDescription.keymasterVersion, child index 2. This is the TA's own
     * version, distinct from attestationVersion, which versions the record
     * schema. Schema v1 has seven members and still carries this at index 2, so
     * the fixed low index resolves on every generation.
     */
    fun parseKeymasterVersion(extensionValue: ByteArray): Int? =
        parseKeyDescriptionInteger(extensionValue, KEYMASTER_VERSION_INDEX)

    /** KeyDescription.attestationVersion. 1..4 are Keymaster, 100 and up are KeyMint. */
    fun parseAttestationVersion(extensionValue: ByteArray): Int? =
        parseKeyDescriptionInteger(extensionValue, ATTESTATION_VERSION_INDEX)

    private fun parseKeyDescriptionInteger(extensionValue: ByteArray, index: Int): Int? {
        val (tagByte, content) = keyDescriptionChild(extensionValue, index) ?: return null
        if (tagByte != TAG_INTEGER) return null
        if (content.isEmpty() || content.size > 4) return null
        if ((content[0].toInt() and 0x80) != 0) return null
        var v = 0
        for (b in content) v = (v shl 8) or (b.toInt() and 0xFF)
        return v
    }

    fun parseAttestationChallenge(extensionValue: ByteArray): ByteArray? {
        val (tagByte, content) =
            keyDescriptionChild(extensionValue, ATTESTATION_CHALLENGE_INDEX) ?: return null
        return if (tagByte == TAG_OCTET_STRING) content else null
    }

    fun parseAttestationSecurityLevel(extensionValue: ByteArray): Int? {
        val (tagByte, content) =
            keyDescriptionChild(extensionValue, ATTESTATION_SECURITY_LEVEL_INDEX) ?: return null
        if (tagByte != TAG_ENUMERATED || content.isEmpty()) return null
        return content[0].toInt() and 0xFF
    }

    fun parseRootOfTrust(extensionValue: ByteArray): RootOfTrust? {
        return try {
            val hardwareEnforced = hardwareEnforcedList(extensionValue) ?: return null
            val rotContent = findTopLevelTaggedContent(hardwareEnforced, ROOT_OF_TRUST_TAG)
                ?: return null
            parseRootOfTrustSequence(rotContent)
        } catch (_: Throwable) {
            null
        }
    }

    private val ROOT_OF_TRUST_TAG = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40.toByte())

    private const val TAG_BOOLEAN = 0x01
    private const val TAG_INTEGER = 0x02
    private const val TAG_OCTET_STRING = 0x04
    private const val TAG_ENUMERATED = 0x0A
    private const val TAG_SEQUENCE = 0x30

    private const val ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3
    /** Matches the snapshot and live-path serial floor of 8 characters. */
    private const val MIN_SERIAL_KEY_LENGTH = 8

    private const val KEY_DESCRIPTION_CHILDREN = 8
    private const val HARDWARE_ENFORCED_INDEX = 7
    private const val SOFTWARE_ENFORCED_INDEX = 6
    private const val SHA256_BYTES = 32

    private const val ATTESTATION_CHALLENGE_INDEX = 4
    private const val ATTESTATION_SECURITY_LEVEL_INDEX = 1
    private const val ATTESTATION_VERSION_INDEX = 0
    private const val KEYMASTER_VERSION_INDEX = 2

    /** KeyMint 3.0, the first release whose VTS requires a boot patch level. */
    const val ATTESTATION_VERSION_KEYMINT_3 = 300

    /**
     * Keymaster 4.0, the generation from which the HAL's Configure() call feeds
     * the TA's patch level from the system property. 1 and 2 are Keymaster 2.0
     * and 3.0, 3 is 4.0, 4 is 4.1, and 100 upward are KeyMint.
     */
    const val ATTESTATION_VERSION_KEYMASTER_4 = 3

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
