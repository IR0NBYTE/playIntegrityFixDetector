package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

class KeyAttestationProbe {
    private val statusClient = AttestationStatusClient()

    private class AttestedKey(val chain: List<X509Certificate>, val challenge: ByteArray)

    data class ProbeOutcome(val mask: Int, val revocation: RevocationStatus)

    /**
     * The probe runs in two parts.
     *
     * The trust gates come first and return immediately, because nothing below
     * them may read fields out of a chain whose crypto or anchoring did not
     * hold. Everything after them accumulates into one mask instead of
     * returning, so a device that trips one finding still gets every other check
     * evaluated. The previous version returned on the first finding, which meant
     * revocation, sitting last, never ran on any device that tripped an earlier
     * check.
     */
    fun probe(
        nativeBitmask: Int,
        onlineRefreshEnabled: Boolean,
        context: Context,
        facts: AttestationAnalysis.DeviceFacts,
        presentation: DeviceIdentity.Presentation,
    ): ProbeOutcome {
        return try {
            val attested = generateAttestedChain() ?: return clean()
            val chain = attested.chain
            if (chain.isEmpty()) return clean()

            // Trust gates. These stay hard early returns.
            if (AttestationAnalysis.chainSignaturesBroken(chain)) return anomaly()
            if (AttestationAnalysis.chainHasNonCaIssuer(chain)) return anomaly()

            val extValue = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
                ?: return clean()

            val securityLevel = AttestationAnalysis.parseAttestationSecurityLevel(extValue)
            val softwareBacked = securityLevel == AttestationAnalysis.SECURITY_LEVEL_SOFTWARE
            val hardwareBacked =
                securityLevel == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    securityLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX

            val googleAnchored =
                AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            if (!softwareBacked && !googleAnchored) return anomaly()

            val challenge = AttestationAnalysis.parseAttestationChallenge(extValue)
            if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
                return anomaly()
            }

            // Accumulate phase. Every check below runs regardless of the others.
            var mask = 0

            // A software-level chain is legitimate on an emulator, a GSI or an
            // AOSP build. It is not legitimate on something presenting as
            // production hardware with a hardware-backed keystore.
            // Anchoring is deliberately NOT part of this condition. A
            // Google-anchored chain that also claims software level is
            // self-contradictory on genuine hardware, and requiring
            // !googleAnchored left exactly that combination in a dead zone where
            // no check ran at all.
            if (softwareBacked && DeviceIdentity.presentsAsPhysicalHardware(presentation)) {
                mask = mask or DetectionResult.DETECTION_ATTEST_SOFTWARE
            }

            // A KeyMint simulator keeps its own record consistent but does not
            // also control the device's properties.
            if (hardwareBacked && googleAnchored &&
                AttestationAnalysis.crossSourceMismatch(extValue, facts).anyMismatch
            ) {
                mask = mask or DetectionResult.DETECTION_ATTEST_CROSS_SOURCE
            }

            // Revocation deliberately sets no detection bit.
            //
            // The published list revokes attestation batch keys, and a batch key
            // is shared by every handset in the production run it was
            // provisioned into. A leaked keybox therefore carries the same
            // serial on a spoofer's chain and on a stock, never-rooted phone
            // from that batch, and 26 of the current entries are SOFTWARE_FLAW,
            // which says the implementation is defective rather than that
            // anyone is spoofing. Flagging on the serial alone would mark those
            // genuine devices permanently. The outcome is reported on its own
            // row instead, where the user can weigh it.
            val revocation = evaluateRevocation(chain, googleAnchored, onlineRefreshEnabled, context)

            val rot = AttestationAnalysis.parseRootOfTrust(extValue)
            if (AttestationAnalysis.isBootContradiction(rot, deviceTampered(nativeBitmask))) {
                mask = mask or DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val propertiesClaimLocked =
                (nativeBitmask and DetectionResult.DETECTION_BOOTLOADER) == 0
            if (hardwareBacked && googleAnchored &&
                AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked)
            ) {
                mask = mask or DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            ProbeOutcome(mask, revocation)
        } catch (e: Throwable) {
            Log.w(TAG, "attestation probe failed; failing safe", e)
            clean()
        } finally {
            deleteKeyQuietly()
        }
    }

    private fun evaluateRevocation(
        chain: List<X509Certificate>,
        googleAnchored: Boolean,
        onlineRefreshEnabled: Boolean,
        context: Context,
    ): RevocationStatus {
        if (!googleAnchored) return RevocationStatus.NOT_APPLICABLE

        val serials = RevocationChecker.serialKeysForChain(chain, AttestationRoots.pinnedRoots)
        if (serials.isEmpty()) return RevocationStatus.NOT_APPLICABLE

        // The offline snapshot is loaded first so that a slow or hostile network
        // can never downgrade a snapshot-backed answer to UNVERIFIABLE.
        val snapshot = RevocationSnapshotLoader.load(context)
        val live = if (onlineRefreshEnabled) statusClient.fetchRevokedSerials() else null

        return RevocationChecker.evaluate(serials, snapshot, live)
    }

    private fun clean() = ProbeOutcome(0, RevocationStatus.NOT_EVALUATED)

    /**
     * A trust gate failed. Revocation was not looked at, which is not the same
     * as knowing the chain had no Google anchor, so the row must not claim it.
     */
    private fun anomaly() =
        ProbeOutcome(DetectionResult.DETECTION_ATTEST_ANOMALY, RevocationStatus.NOT_EVALUATED)

    private fun deviceTampered(nativeBitmask: Int): Boolean {
        return (nativeBitmask and DetectionResult.DETECTION_ROOT_HIDER) != 0
    }

    private fun generateAttestedChain(): AttestedKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)

        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        generator.generateKeyPair()

        val raw = keyStore.getCertificateChain(KEY_ALIAS) ?: return null
        return AttestedKey(raw.mapNotNull { it as? X509Certificate }, challenge)
    }

    private fun deleteKeyQuietly() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val TAG = "KeyAttestationProbe"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "pifd_attest_probe"
    }
}
