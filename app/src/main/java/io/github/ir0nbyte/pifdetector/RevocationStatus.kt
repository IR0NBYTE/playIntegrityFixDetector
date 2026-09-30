package io.github.ir0nbyte.pifdetector

/**
 * Outcome of checking a chain's certificate serials against Google's published
 * key revocation list.
 *
 * A VERIFIED result means the serials are not on the published list. It does not
 * mean the keybox is genuine: Google publishes a revocation some time after a
 * keybox is known to be compromised, so a freshly rotated keybox is routinely
 * absent from the list. Treat VERIFIED as "not known-bad".
 */
enum class RevocationOutcome {
    /** No Google-anchored attestation chain was available to check. */
    NOT_APPLICABLE,

    /**
     * An earlier trust gate failed, so the chain was never examined for
     * revocation. Distinct from NOT_APPLICABLE, which is a statement about the
     * chain's anchoring that those gates have not established.
     */
    NOT_EVALUATED,

    /** Checked against at least one usable source; no serial was listed. */
    VERIFIED,

    /** At least one serial in the chain is on the published list. */
    KNOWN_REVOKED,

    /** Neither the bundled snapshot nor the network could be consulted. */
    UNVERIFIABLE,
}

data class RevocationStatus(
    val outcome: RevocationOutcome,
    val snapshotDate: String?,
    val snapshotEntryCount: Int,
    val networkConsulted: Boolean,
) {
    companion object {
        val NOT_APPLICABLE = RevocationStatus(
            RevocationOutcome.NOT_APPLICABLE,
            snapshotDate = null,
            snapshotEntryCount = 0,
            networkConsulted = false,
        )

        val NOT_EVALUATED = RevocationStatus(
            RevocationOutcome.NOT_EVALUATED,
            snapshotDate = null,
            snapshotEntryCount = 0,
            networkConsulted = false,
        )
    }
}
