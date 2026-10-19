package io.github.ir0nbyte.pifdetector

import java.security.cert.X509Certificate

/**
 * The decision table for asking the same keystore the same question twice, once
 * for EC and once for RSA, and comparing where the two answers come from.
 *
 * A keybox is one file holding one key per algorithm, signed into a chain by
 * whoever provisioned it. Nothing in the KeyMint HAL requires the two chains to
 * share a root, and on the AOSP software implementation they deliberately do
 * not, so this table never asks whether the roots are equal. It asks a narrower
 * question with only one answer on genuine hardware: having established that
 * the EC chain is hardware-backed and ends in a Google attestation root, does
 * the RSA chain from the same keystore end in a certificate AOSP ships for
 * devices that have no secure environment at all.
 *
 * A device cannot be both. The EC answer says a secure environment holds a
 * Google-provisioned batch key; the RSA answer would say the same keystore has
 * nothing better than the software fallback. One keystore cannot be in both
 * states at once, and no stock handset has to choose.
 *
 * Why the question exists. OhMyKeymint stopped requiring an RSA entry in the
 * keybox on 2026-10-18 and falls back to its bundled template when one is
 * absent, and that template is the AOSP software chain. So a keybox carrying
 * only EC produces exactly this split. Whoever ships a software KeyMint can
 * close it in an afternoon by refusing to serve RSA at all, which is why the
 * absent case below is deliberately not a finding.
 *
 * What is deliberately NOT reported:
 *
 * - A refusal. A keystore that will not serve an attested RSA key may be out of
 *   remotely provisioned keys, or may not support RSA attestation on this
 *   generation. The honest reading is "could not tell", as with
 *   [StrongBoxCheck] and a StrongBox refusal.
 * - An unrecognised root. A chain ending somewhere this build has never heard
 *   of is reported and left alone. The pinned set is only as complete as the
 *   day it was assembled, and a root Google adds tomorrow must not read as a
 *   forgery. [RootOrigin.UNRECOGNISED] is also where a companion chain whose
 *   signatures do not verify lands, because a chain that does not hold together
 *   cannot be trusted to say what its own root is.
 * - Anything at all when the EC chain is not itself hardware-backed and
 *   Google-anchored. Without that, there is no contradiction to find: an
 *   emulator serving software chains for both algorithms is being honest.
 *
 * Deliberately Android-free and side-effect-free so the whole table is unit
 * testable. [CompanionAlgorithmProbe] does the generating and hands the results
 * here.
 */
object CompanionAlgorithmCheck {

    /**
     * Where a chain's top certificate came from, identified positively.
     *
     * Every value but [UNRECOGNISED] requires the certificate to BE an instance
     * of a known root, through [AttestationAnalysis.isAnchorInstance], rather
     * than merely to carry its key. An empty root list yields [UNRECOGNISED]
     * rather than a match, so a build whose PEMs failed to parse fires nothing.
     */
    enum class RootOrigin {
        /** An instance of a pinned Google attestation root. */
        GOOGLE_PINNED,

        /** An instance of a root AOSP compiles into its software KeyMaster. */
        AOSP_SOFTWARE,

        /** A root this build does not recognise, or a chain that does not hold. */
        UNRECOGNISED,

        /** No chain to classify. */
        ABSENT,
    }

    enum class Verdict(val isFinding: Boolean) {
        /** The EC chain did not meet the precondition, so nothing was asked. */
        NOT_EVALUATED(false),

        /** Both algorithms came from a Google root. Nothing to say. */
        AGREED(false),

        /** The keystore would not serve an attested RSA key. Could not tell. */
        COMPANION_REFUSED(false),

        /** The RSA chain ends somewhere unfamiliar. Reported, not judged. */
        COMPANION_UNRECOGNISED(false),

        /** The finding: Google-rooted EC beside a software-rooted RSA. */
        COMPANION_SOFTWARE_ROOTED(true),
    }

    /**
     * Classifies the top of a chain.
     *
     * @param top the chain's last certificate, or null when there is no chain.
     * @param googleAnchorKeys from [AttestationAnalysis.anchorKeyEncodings] over
     *   [AttestationRoots.pinnedRoots].
     * @param softwareAnchorKeys the same over [SoftwareAttestationRoots.roots].
     */
    fun classifyRoot(
        top: X509Certificate?,
        googleAnchorKeys: Set<List<Byte>>,
        softwareAnchorKeys: Set<List<Byte>>,
    ): RootOrigin {
        if (top == null) return RootOrigin.ABSENT
        if (AttestationAnalysis.isAnchorInstance(top, googleAnchorKeys)) {
            return RootOrigin.GOOGLE_PINNED
        }
        if (AttestationAnalysis.isAnchorInstance(top, softwareAnchorKeys)) {
            return RootOrigin.AOSP_SOFTWARE
        }
        return RootOrigin.UNRECOGNISED
    }

    /**
     * Whether the second generation is worth the keystore round trip at all.
     *
     * Checked before the companion key is requested rather than after, so a
     * device that cannot produce the contradiction never pays for an RSA
     * keygen. On the bench that is every emulator.
     */
    fun worthAsking(primaryOrigin: RootOrigin, primaryHardwareBacked: Boolean): Boolean =
        primaryOrigin == RootOrigin.GOOGLE_PINNED && primaryHardwareBacked

    fun evaluate(
        primaryOrigin: RootOrigin,
        primaryHardwareBacked: Boolean,
        companionOrigin: RootOrigin,
    ): Verdict {
        if (!worthAsking(primaryOrigin, primaryHardwareBacked)) return Verdict.NOT_EVALUATED
        return when (companionOrigin) {
            RootOrigin.ABSENT -> Verdict.COMPANION_REFUSED
            RootOrigin.GOOGLE_PINNED -> Verdict.AGREED
            RootOrigin.AOSP_SOFTWARE -> Verdict.COMPANION_SOFTWARE_ROOTED
            RootOrigin.UNRECOGNISED -> Verdict.COMPANION_UNRECOGNISED
        }
    }

    /** The bit this check contributes, for a verdict. */
    fun mask(verdict: Verdict): Int =
        if (verdict.isFinding) DetectionResult.DETECTION_ATTEST_FORGERY else 0

    /** The reason codes this check contributes, for a verdict. */
    fun reasons(verdict: Verdict): List<Int> =
        if (verdict == Verdict.COMPANION_SOFTWARE_ROOTED) listOf(COMPANION_SOFTWARE_ROOT) else emptyList()

    /** The software fallback served beside a Google-rooted hardware chain. */
    const val COMPANION_SOFTWARE_ROOT = 1113

    val REASON_CODES: Set<Int> = setOf(
        COMPANION_SOFTWARE_ROOT,
    )
}
