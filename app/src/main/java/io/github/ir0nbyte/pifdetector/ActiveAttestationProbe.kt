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

    /**
     * What one run found. Every forgery arm names itself with a reason code
     * and the mask is derived from that code, so the row can never light up
     * without saying which arm lit it. The software-backed outcome carries no
     * reason: it is a readout of where the key lives, not a forgery arm.
     */
    data class Outcome(val mask: Int, val reasons: List<Int>) {
        companion object {
            val NONE = Outcome(0, emptyList())

            /** The software-backed readout, which names no arm. */
            val SOFTWARE = Outcome(DetectionResult.DETECTION_ATTEST_SOFTWARE, emptyList())

            /** An arm that fired, its mask taken from the code's own row. */
            fun of(reason: Int): Outcome =
                Outcome(ReasonCodes.flagOf(reason) ?: 0, listOf(reason))
        }
    }

    fun probe(passiveProbeFlagged: Boolean, presentation: DeviceIdentity.Presentation): Outcome {
        return try {
            attestKeyProvocation(passiveProbeFlagged, presentation).takeIf { it.mask != 0 }
                ?: authRequiredProvocation()
        } catch (e: Throwable) {
            Log.w(TAG, "active attestation probe failed; failing safe", e)
            Outcome.NONE
        }
    }

    private fun attestKeyProvocation(
        passiveProbeFlagged: Boolean,
        presentation: DeviceIdentity.Presentation,
    ): Outcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return Outcome.NONE
        val attested = generate(ALIAS_ATTEST_KEY) { builder ->
            builder.setDigests(KeyProperties.DIGEST_SHA256)
        } ?: return Outcome.NONE

        val chain = attested.chain
        if (chain.isEmpty()) return Outcome.NONE

        if (AttestationAnalysis.isSelfSignedSingleCert(chain)) {
            return Outcome.of(REASON_ATTEST_KEY_SELF_SIGNED_SINGLE)
        }

        chainStructureForgery(
            chain, REASON_ATTEST_KEY_SIGNATURE_BROKEN, REASON_ATTEST_KEY_NON_CA_ISSUER
        )?.let { return it }

        val ext = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
            ?: return Outcome.NONE

        val challenge = AttestationAnalysis.parseAttestationChallenge(ext)
        if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
            return Outcome.of(REASON_ATTEST_KEY_CHALLENGE_MISMATCH)
        }

        if (!passiveProbeFlagged) {
            val softwareBacked =
                AttestationAnalysis.parseAttestationSecurityLevel(ext) ==
                    AttestationAnalysis.SECURITY_LEVEL_SOFTWARE
            val anchored =
                AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            if (!anchored) {
                if (!softwareBacked) return Outcome.of(REASON_ATTEST_KEY_HARDWARE_UNANCHORED)
                if (DeviceIdentity.presentsAsPhysicalHardware(presentation)) {
                    return Outcome.SOFTWARE
                }
            }
        }

        return Outcome.NONE
    }

    private fun chainStructureForgery(
        chain: List<X509Certificate>,
        signatureBroken: Int,
        nonCaIssuer: Int,
    ): Outcome? {
        if (AttestationAnalysis.chainSignaturesBroken(chain)) {
            return Outcome.of(signatureBroken)
        }
        if (AttestationAnalysis.chainHasNonCaIssuer(chain)) {
            return Outcome.of(nonCaIssuer)
        }
        return null
    }

    @Suppress("DEPRECATION")
    private fun authRequiredProvocation(): Outcome {
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
        } ?: return Outcome.NONE

        val chain = attested.chain
        if (chain.isEmpty()) return Outcome.NONE

        if (AttestationAnalysis.isSelfSignedSingleCert(chain)) {
            return Outcome.of(REASON_AUTH_BOUND_SELF_SIGNED_SINGLE)
        }

        chainStructureForgery(
            chain, REASON_AUTH_BOUND_SIGNATURE_BROKEN, REASON_AUTH_BOUND_NON_CA_ISSUER
        )?.let { return it }

        val ext = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
            ?: return Outcome.NONE

        if (chain.size >= 2 &&
            AttestationAnalysis.leafSignatureTracksRequestedDigest(chain[0].sigAlgName)
        ) {
            return Outcome.of(REASON_AUTH_BOUND_LEAF_USED_REQUESTED_DIGEST)
        }

        val challenge = AttestationAnalysis.parseAttestationChallenge(ext)
        if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
            return Outcome.of(REASON_AUTH_BOUND_CHALLENGE_MISMATCH)
        }

        if (AttestationAnalysis.authRequirementContradiction(ext)) {
            return Outcome.of(REASON_AUTH_BOUND_AUTH_CONTRADICTION)
        }

        return Outcome.NONE
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

    companion object {
        private const val TAG = "ActiveAttestProbe"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS_ATTEST_KEY = "pifd_probe_attestkey"
        private const val ALIAS_AUTH_BOUND = "pifd_probe_authbound"
        private const val AUTH_VALIDITY_SECONDS = 60

        /**
         * One code per forgery arm, all on the forgery row. The two
         * provocations run the same structural checks, so each gets its own
         * codes and a report says which request exposed the chain.
         * Append-only.
         */
        const val REASON_ATTEST_KEY_SELF_SIGNED_SINGLE = 1114
        const val REASON_ATTEST_KEY_SIGNATURE_BROKEN = 1115
        const val REASON_ATTEST_KEY_NON_CA_ISSUER = 1116
        const val REASON_ATTEST_KEY_CHALLENGE_MISMATCH = 1117
        const val REASON_ATTEST_KEY_HARDWARE_UNANCHORED = 1118
        const val REASON_AUTH_BOUND_SELF_SIGNED_SINGLE = 1119
        const val REASON_AUTH_BOUND_SIGNATURE_BROKEN = 1120
        const val REASON_AUTH_BOUND_NON_CA_ISSUER = 1121
        const val REASON_AUTH_BOUND_LEAF_USED_REQUESTED_DIGEST = 1122
        const val REASON_AUTH_BOUND_CHALLENGE_MISMATCH = 1123
        const val REASON_AUTH_BOUND_AUTH_CONTRADICTION = 1124

        val REASON_CODES: Set<Int> = setOf(
            REASON_ATTEST_KEY_SELF_SIGNED_SINGLE,
            REASON_ATTEST_KEY_SIGNATURE_BROKEN,
            REASON_ATTEST_KEY_NON_CA_ISSUER,
            REASON_ATTEST_KEY_CHALLENGE_MISMATCH,
            REASON_ATTEST_KEY_HARDWARE_UNANCHORED,
            REASON_AUTH_BOUND_SELF_SIGNED_SINGLE,
            REASON_AUTH_BOUND_SIGNATURE_BROKEN,
            REASON_AUTH_BOUND_NON_CA_ISSUER,
            REASON_AUTH_BOUND_LEAF_USED_REQUESTED_DIGEST,
            REASON_AUTH_BOUND_CHALLENGE_MISMATCH,
            REASON_AUTH_BOUND_AUTH_CONTRADICTION,
        )
    }
}
