package io.github.ir0nbyte.pifdetector

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

    fun probe(nativeBitmask: Int, revocationEnabled: Boolean): Int {
        return try {
            val attested = generateAttestedChain() ?: return 0
            val chain = attested.chain
            if (chain.isEmpty()) return 0

            if (AttestationAnalysis.chainSignaturesBroken(chain)) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }
            if (AttestationAnalysis.chainHasNonCaIssuer(chain)) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val extValue = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
                ?: return 0

            val securityLevel = AttestationAnalysis.parseAttestationSecurityLevel(extValue)
            val softwareBacked = securityLevel == AttestationAnalysis.SECURITY_LEVEL_SOFTWARE

            val hardwareBacked =
                securityLevel == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    securityLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX

            val googleAnchored =
                AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            if (!softwareBacked && !googleAnchored) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val challenge = AttestationAnalysis.parseAttestationChallenge(extValue)
            if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val rot = AttestationAnalysis.parseRootOfTrust(extValue)
            if (AttestationAnalysis.isBootContradiction(rot, deviceTampered(nativeBitmask))) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val propertiesClaimLocked =
                (nativeBitmask and DetectionResult.DETECTION_BOOTLOADER) == 0
            if (hardwareBacked && googleAnchored &&
                AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked)
            ) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            if (revocationEnabled && googleAnchored) {
                val revoked = statusClient.fetchRevokedSerials()
                if (revoked != null) {
                    val serials =
                        chain.flatMap { AttestationAnalysis.serialLookupKeys(it.serialNumber) }
                    if (AttestationAnalysis.anyCertRevoked(serials, revoked)) {
                        return DetectionResult.DETECTION_ATTEST_ANOMALY
                    }
                }
            }

            0
        } catch (e: Throwable) {
            Log.w(TAG, "attestation probe failed; failing safe", e)
            0
        } finally {
            deleteKeyQuietly()
        }
    }

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
