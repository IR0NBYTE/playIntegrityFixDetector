package io.github.ir0nbyte.pifdetector

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

class ActiveAttestationProbe {
    private class Attested(val chain: List<X509Certificate>, val challenge: ByteArray)

    fun probe(passiveProbeFlagged: Boolean, presentation: DeviceIdentity.Presentation): Int {
        return try {
            attestKeyProvocation(passiveProbeFlagged, presentation).takeIf { it != 0 }
                ?: authRequiredProvocation()
        } catch (e: Throwable) {
            Log.w(TAG, "active attestation probe failed; failing safe", e)
            0
        }
    }

    private fun attestKeyProvocation(
        passiveProbeFlagged: Boolean,
        presentation: DeviceIdentity.Presentation,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return 0
        val attested = generate(ALIAS_ATTEST_KEY) { builder ->
            builder.setDigests(KeyProperties.DIGEST_SHA256)
        } ?: return 0

        val chain = attested.chain
        if (chain.isEmpty()) return 0

        if (AttestationAnalysis.isSelfSignedSingleCert(chain)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        chainStructureForgery(chain)?.let { return it }

        val ext = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID) ?: return 0

        val challenge = AttestationAnalysis.parseAttestationChallenge(ext)
        if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        if (!passiveProbeFlagged) {
            val softwareBacked =
                AttestationAnalysis.parseAttestationSecurityLevel(ext) ==
                    AttestationAnalysis.SECURITY_LEVEL_SOFTWARE
            val anchored =
                AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            if (!anchored) {
                if (!softwareBacked) return DetectionResult.DETECTION_ATTEST_FORGERY
                if (DeviceIdentity.presentsAsPhysicalHardware(presentation)) {
                    return DetectionResult.DETECTION_ATTEST_SOFTWARE
                }
            }
        }

        return 0
    }

    private fun chainStructureForgery(chain: List<X509Certificate>): Int? {
        if (AttestationAnalysis.chainSignaturesBroken(chain)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }
        if (AttestationAnalysis.chainHasNonCaIssuer(chain)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }
        return null
    }

    @Suppress("DEPRECATION")
    private fun authRequiredProvocation(): Int {
        val attested = generate(ALIAS_AUTH_BOUND) { builder ->
            builder.setDigests(KeyProperties.DIGEST_SHA512)
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    AUTH_VALIDITY_SECONDS,
                    KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                builder.setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS)
            }
        } ?: return 0

        val chain = attested.chain
        if (chain.isEmpty()) return 0

        if (AttestationAnalysis.isSelfSignedSingleCert(chain)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        chainStructureForgery(chain)?.let { return it }

        val ext = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID) ?: return 0

        if (chain.size >= 2 &&
            AttestationAnalysis.leafSignatureTracksRequestedDigest(chain[0].sigAlgName)
        ) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        val challenge = AttestationAnalysis.parseAttestationChallenge(ext)
        if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        if (AttestationAnalysis.authRequirementContradiction(ext)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        return 0
    }

    private fun generate(
        alias: String,
        configure: (KeyGenParameterSpec.Builder) -> Unit
    ): Attested? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

            val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val purposes = if (alias == ALIAS_ATTEST_KEY) {
                KeyProperties.PURPOSE_ATTEST_KEY
            } else {
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            }
            val builder = KeyGenParameterSpec.Builder(alias, purposes)
                .setAttestationChallenge(challenge)
            configure(builder)

            val generator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            generator.initialize(builder.build())
            generator.generateKeyPair()

            val raw = keyStore.getCertificateChain(alias) ?: return null
            Attested(raw.mapNotNull { it as? X509Certificate }, challenge)
        } catch (e: Exception) {
            Log.d(TAG, "provocation '$alias' unavailable on this device", e)
            null
        } finally {
            deleteQuietly(alias)
        }
    }

    private fun deleteQuietly(alias: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val TAG = "ActiveAttestProbe"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_ATTEST_KEY = "pifd_probe_attestkey"
        const val ALIAS_AUTH_BOUND = "pifd_probe_authbound"
        const val AUTH_VALIDITY_SECONDS = 60
    }
}
