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
     * is byte identical to a pinned Google root.
     *
     * A trust anchor appears in the chain of every genuine device. If Google ever
     * revokes one, that is a fleet wide CA event rather than evidence about this
     * device, and including it here would flag every honest user at once.
     */
    fun serialKeysForChain(
        chain: List<X509Certificate>,
        pinnedRoots: List<X509Certificate>,
    ): List<String> {
        val pinnedEncodings = pinnedRoots.mapNotNull { root ->
            try {
                root.encoded?.toList()
            } catch (_: Exception) {
                null
            }
        }
        return chain.filterNot { cert -> isPinnedRoot(cert, pinnedEncodings) }
            .flatMap { AttestationAnalysis.serialLookupKeys(it.serialNumber) }
    }

    private fun isPinnedRoot(
        cert: X509Certificate,
        pinnedEncodings: List<List<Byte>>,
    ): Boolean {
        val encoded = try {
            cert.encoded?.toList()
        } catch (_: Exception) {
            null
        } ?: return false
        return pinnedEncodings.any { it == encoded }
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
