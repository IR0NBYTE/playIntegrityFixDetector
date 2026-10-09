package io.github.ir0nbyte.pifdetector

import java.security.cert.X509Certificate

/**
 * Decides the revocation outcome for one attestation chain.
 *
 * Pure logic with no Android and no I/O of its own, so the whole decision table
 * is unit testable. Callers supply whichever sources they managed to obtain.
 */
object RevocationChecker {

    /**
     * Collects the serial lookup keys for a chain, skipping any certificate that
     * is an instance of a pinned Google root.
     *
     * A trust anchor appears in the chain of every genuine device. If Google ever
     * revokes one, that is a fleet wide CA event rather than evidence about this
     * device, and including it here would flag every honest user at once.
     *
     * The comparison is by public key rather than by encoded bytes because
     * Google issues one attestation key as several certificates with different
     * windows, and a handset keeps serving the instance it was provisioned
     * with. Byte identity therefore skipped the instance this build happens to
     * embed and submitted the others, which are the same key and the same CA,
     * for revocation lookup. No root serial is on the current published list,
     * so this was a latent mismatch rather than a false positive anyone saw.
     *
     * The skip needs the certificate to be a root INSTANCE, not merely to
     * carry an anchor's key, so it goes through
     * [AttestationAnalysis.isAnchorInstance]. A leaked keybox can sign a leaf
     * whose public key is a Google root's, and that chain verifies and anchors;
     * keying the skip on the public key alone would let such a leaf hide its
     * own serial. Requiring self-signature, which every published root has,
     * keeps the skip to the certificates it is for.
     */
    fun serialKeysForChain(
        chain: List<X509Certificate>,
        pinnedRoots: List<X509Certificate>,
    ): List<String> {
        val anchorKeys = AttestationAnalysis.anchorKeyEncodings(pinnedRoots)
        return chain.filterNot { AttestationAnalysis.isAnchorInstance(it, anchorKeys) }
            .flatMap { AttestationAnalysis.serialLookupKeys(it.serialNumber) }
    }

    /**
     * @param chainSerialKeys serial lookup keys, already filtered by [serialKeysForChain]
     * @param snapshot the bundled offline list, or null when it is missing or unusable
     * @param liveSerials the freshly fetched list, or null when the network was not
     *   consulted or returned something unusable
     */
    fun evaluate(
        chainSerialKeys: List<String>,
        snapshot: RevocationSnapshot.Snapshot?,
        liveSerials: Set<String>?,
    ): RevocationStatus {
        val networkConsulted = liveSerials != null

        if (snapshot == null && liveSerials == null) {
            return RevocationStatus(
                RevocationOutcome.UNVERIFIABLE,
                snapshotDate = null,
                snapshotEntryCount = 0,
                networkConsulted = networkConsulted,
            )
        }

        val union = HashSet<String>()
        snapshot?.serials?.let { union.addAll(it) }
        liveSerials?.let { union.addAll(it) }

        val outcome = if (AttestationAnalysis.anyCertRevoked(chainSerialKeys, union)) {
            RevocationOutcome.KNOWN_REVOKED
        } else {
            RevocationOutcome.VERIFIED
        }

        return RevocationStatus(
            outcome = outcome,
            snapshotDate = snapshot?.fetchedDate,
            snapshotEntryCount = snapshot?.serials?.size ?: 0,
            networkConsulted = networkConsulted,
        )
    }
}
