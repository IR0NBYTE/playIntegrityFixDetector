package io.github.ir0nbyte.pifdetector

/**
 * What a single check concluded on this run.
 *
 * This replaces the set of independent booleans the row used to carry. Those
 * could express combinations that have no meaning, such as a check that both
 * could not apply to the device and made a real observation, and the two places
 * that read them had to re-derive a precedence order separately. They disagreed:
 * the list ranked an informational row above one that could not apply, and the
 * summary card ranked them the other way. Nothing set both at once, so the
 * disagreement never surfaced, but only because of how the callers happened to
 * be written. One field removes the question.
 *
 * The flags in [DetectionResult] remain the single source of truth for which
 * bits the native engine set. A state is what the Kotlin layer concluded on top
 * of that, including the outcomes only it can know.
 */
enum class CheckState(
    /** A finding about this device. Only [DETECTED] counts. */
    val isFinding: Boolean,
    /** False when this device cannot produce evidence for the check at all. */
    val isObservable: Boolean,
    /** Observable, ran or tried to run, and did not resolve to a pass. */
    val needsReview: Boolean,
) {
    /** A bit is set, or the row's own analysis convicted. */
    DETECTED(isFinding = true, isObservable = true, needsReview = false),

    /**
     * A real observation worth showing that is not by itself evidence about
     * this device, such as a serial on the revocation list, where the same
     * batch key is shared with every handset in its production run.
     */
    INFORMATIONAL(isFinding = false, isObservable = true, needsReview = true),

    /** Observable in principle; this run reached no verdict. Not a pass. */
    UNVERIFIABLE(isFinding = false, isObservable = true, needsReview = true),

    /**
     * Never ran, because a precondition failed. Distinct from [UNVERIFIABLE],
     * which tried and could not conclude. Both are counted for review, because
     * a check that did not execute has not passed anything.
     */
    SKIPPED(isFinding = false, isObservable = true, needsReview = true),

    /**
     * Cannot be observed on this device: it needs privilege the app does not
     * have, or a platform surface this device does not expose. Kept out of the
     * pass count so the summary never claims coverage the sandbox forbids, and
     * out of the review count so a stock phone does not read amber for lacking
     * a surface it was never going to have.
     */
    NOT_OBSERVABLE(isFinding = false, isObservable = false, needsReview = false),

    /** Ran, and found nothing. */
    CLEAN(isFinding = false, isObservable = true, needsReview = false),
}
