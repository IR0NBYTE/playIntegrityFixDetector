package io.github.ir0nbyte.pifdetector

/**
 * The decision table for the keystore boundary probes.
 *
 * Every other attestation check reads a record the keystore volunteered. These
 * ask for something awkward instead and judge the answer, because a
 * reimplementation has to reproduce behaviour its authors may not have read the
 * contract for. Both arms here are quoted from the KeyMint HAL rather than
 * inferred, and both were measured on two independent KeyMint implementations
 * before anything was written against them.
 *
 * Deliberately Android-free and side-effect-free so the whole table is unit
 * testable. [KeystoreBoundaryProbe] does the generating and hands the results
 * here.
 *
 * Both arms land on DETECTION_ATTEST_FORGERY rather than on a flag of their
 * own: the finding is that the keystore's answer contradicts a platform
 * guarantee, which is what that flag already means in this codebase. The reason
 * codes are what tell a report which boundary gave way.
 */
object KeystoreBoundary {

    /**
     * Tag.aidl, Tag::ATTESTATION_CHALLENGE: "The challenge value may be up to
     * 128 bytes. If the caller provides a bigger challenge, INVALID_INPUT_LENGTH
     * error should be returned."
     */
    const val MAX_CHALLENGE_BYTES = 128

    /** A key generated with no attestation challenge at all. */
    data class NoChallengeShape(
        val selfSigned: Boolean,
        val carriesAttestationRecord: Boolean,
    )

    /**
     * A key generated with an attestation challenge of some size.
     *
     * [securityLevel] is the level the resulting record claims, or null when
     * the request was refused or came back with no record at all. Keeping it
     * nullable rather than collapsing it to a boolean matters: "no record"
     * and "a software record" are different observations, and only the second
     * one is a downgrade.
     */
    data class ChallengeOutcome(
        val accepted: Boolean,
        val securityLevel: Int?,
    ) {
        val hardwareBacked: Boolean
            get() = securityLevel == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                securityLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX

        val softwareBacked: Boolean
            get() = securityLevel == AttestationAnalysis.SECURITY_LEVEL_SOFTWARE
    }

    /**
     * What the keystore did. A null field means the request could not be made
     * on this device, which is never a finding: an arm that could not run says
     * nothing rather than guessing.
     */
    data class Observation(
        val noChallenge: NoChallengeShape? = null,
        val legalChallenge: ChallengeOutcome? = null,
        val overLimitChallenge: ChallengeOutcome? = null,
    )

    data class Verdict(val mask: Int, val reasons: List<Int>) {
        val isFinding: Boolean get() = mask != 0
    }

    fun evaluate(observation: Observation): Verdict {
        val reasons = ArrayList<Int>(2)

        // IKeyMintDevice::generateKey returns the certificate chain itself, so
        // this is KeyMint's own answer and not something the framework
        // synthesises on its behalf. With no challenge there is nothing to
        // attest, so a record cannot legitimately exist.
        observation.noChallenge?.let { shape ->
            if (shape.carriesAttestationRecord) reasons.add(REASON_NO_CHALLENGE_RECORD)
            if (!shape.selfSigned) reasons.add(REASON_NO_CHALLENGE_NOT_SELF_SIGNED)
        }

        val over = observation.overLimitChallenge
        if (over != null && over.accepted) {
            reasons.add(REASON_OVER_LIMIT_ACCEPTED)

            // The sharper half of the same observation. Silently serving an
            // over-limit request from software, while a legal one came from
            // hardware, is a downgrade inside one device rather than a
            // difference of opinion about the limit.
            //
            // This needs the over-limit record to SAY software, not merely to
            // fail to say hardware. An accepted request that came back with no
            // record at all is a different anomaly, and claiming a downgrade
            // for it would put words in the report that the evidence does not
            // support.
            val legal = observation.legalChallenge
            if (over.softwareBacked && legal != null && legal.accepted && legal.hardwareBacked) {
                reasons.add(REASON_OVER_LIMIT_DOWNGRADED)
            }
        }

        val mask = if (reasons.isEmpty()) 0 else DetectionResult.DETECTION_ATTEST_FORGERY
        return Verdict(mask, reasons)
    }

    const val REASON_NO_CHALLENGE_RECORD = 1101
    const val REASON_NO_CHALLENGE_NOT_SELF_SIGNED = 1102
    const val REASON_OVER_LIMIT_ACCEPTED = 1103
    const val REASON_OVER_LIMIT_DOWNGRADED = 1104

    /**
     * Every code this probe can emit. [ReasonCodesSyncTest] unions this with the
     * native constants, so a code with no producer and a producer with no text
     * both fail the build.
     */
    val REASON_CODES: Set<Int> = setOf(
        REASON_NO_CHALLENGE_RECORD,
        REASON_NO_CHALLENGE_NOT_SELF_SIGNED,
        REASON_OVER_LIMIT_ACCEPTED,
        REASON_OVER_LIMIT_DOWNGRADED,
    )
}
