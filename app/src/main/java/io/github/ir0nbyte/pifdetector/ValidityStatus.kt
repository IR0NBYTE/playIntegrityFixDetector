package io.github.ir0nbyte.pifdetector

/**
 * Outcome of examining the validity windows of an attestation chain's issuer
 * certificates.
 *
 * Only one outcome is a finding. An EXPIRED issuer deliberately is not, for two
 * independent reasons.
 *
 * Google's own key-attestation guidance tells verifiers to trust a chain that
 * terminates in the published attestation roots "regardless of certificate
 * validity period", under the heading that expired factory keys are still
 * trustworthy. Flagging an expired issuer would therefore mark devices Google
 * documents as genuine.
 *
 * And a batch or intermediate certificate is shared by every handset in the
 * production run it was provisioned into, so an aged-out certificate appears
 * identically on a spoofer's chain and on a stock phone from that run. It is
 * the same shared-material argument that keeps a revoked serial off the
 * verdict.
 *
 * An inverted or zero-width window is different in kind: no certificate
 * authority emits one, and recognising it needs no clock at all.
 */
enum class ValidityOutcome {
    /**
     * No chain, or a chain whose issuer windows cannot be judged against a
     * reference: not anchored, not hardware-backed, or no issuers at all.
     *
     * Note this does NOT mean such a chain can never set the bit. The
     * inverted-window arm is evaluated before the anchoring and
     * hardware-backed gates, deliberately: a forged chain is exactly the case
     * that would fail an anchoring gate. It is still gated on the embedded
     * root set having parsed, because without that the issuer list cannot have
     * trust anchors excluded from it.
     */
    NOT_APPLICABLE,

    /** An earlier trust gate failed, so the windows were never examined. */
    NOT_EVALUATED,

    /** Examined against a clock-independent floor; nothing anomalous. */
    VERIFIED,

    /**
     * An issuer's notBefore is at or after its notAfter. The only outcome that
     * sets a detection bit.
     */
    IMPOSSIBLE_WINDOW,

    /**
     * An issuer aged out well before the floor. Reported with the shared-batch
     * caveat; never a finding.
     */
    EXPIRED_ISSUER,

    /**
     * An issuer lapsed only recently. A remotely provisioned certificate that
     * lagged a rotation looks identical, so this is never called.
     */
    RECENTLY_EXPIRED,

    /**
     * The device clock is behind the floor, which is the condition under which
     * a genuine device serves a lapsed certificate. Suppresses the expiry
     * outcomes rather than compounding them.
     */
    CLOCK_BEHIND,

    /** No clock-independent floor could be established, so nothing was judged. */
    NO_REFERENCE,
}

data class ValidityStatus(
    val outcome: ValidityOutcome,
    /** Subject of the certificate the outcome refers to, for the row detail. */
    val offenderSubject: String? = null,
    /** How far past the floor the offender lapsed, in days. */
    val daysPastFloor: Long? = null,
) {
    val isFinding: Boolean get() = outcome == ValidityOutcome.IMPOSSIBLE_WINDOW

    companion object {
        val NOT_APPLICABLE = ValidityStatus(ValidityOutcome.NOT_APPLICABLE)
        val NOT_EVALUATED = ValidityStatus(ValidityOutcome.NOT_EVALUATED)
        val NO_REFERENCE = ValidityStatus(ValidityOutcome.NO_REFERENCE)
    }
}
