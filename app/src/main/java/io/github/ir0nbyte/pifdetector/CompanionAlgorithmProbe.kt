package io.github.ir0nbyte.pifdetector

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * Asks the keystore for an attested key twice, once EC and once RSA, and hands
 * the two chains' roots to [CompanionAlgorithmCheck].
 *
 * The EC request goes first because it is the cheaper one and because it is the
 * gate: unless its chain is hardware-backed and ends in a Google attestation
 * root, there is no contradiction available and the RSA request is never made.
 * On the bench that short circuit is what keeps the probe free on every
 * emulator image.
 *
 * Both keys are deleted in a finally block whether or not the probe reached a
 * verdict, and the probe fails clean on any throwable, as the other keystore
 * probes do: an exception on a keystore call says nothing about the device.
 */
class CompanionAlgorithmProbe {

    data class ProbeOutcome(
        val mask: Int = 0,
        val reasons: List<Int> = emptyList(),
        val verdict: CompanionAlgorithmCheck.Verdict = CompanionAlgorithmCheck.Verdict.NOT_EVALUATED,
    )

    /**
     * What the keystore actually answered, before the table judged it.
     *
     * Separated out so an instrumented test can assert the arms RAN on this
     * device rather than only that they stayed quiet. A probe that quietly
     * skipped everything reports clean for the wrong reason.
     *
     * [primaryChainLength] is zero when the EC request itself failed, which is
     * the one case that is indistinguishable from a device with no keystore.
     */
    data class Observation(
        val primaryChainLength: Int,
        val primaryOrigin: CompanionAlgorithmCheck.RootOrigin,
        val primaryHardwareBacked: Boolean,
        val companionRequested: Boolean,
        val companionChainLength: Int,
        val companionOrigin: CompanionAlgorithmCheck.RootOrigin,
    )

    fun probe(): ProbeOutcome {
        val observation = observe()
        val verdict = CompanionAlgorithmCheck.evaluate(
            observation.primaryOrigin,
            observation.primaryHardwareBacked,
            observation.companionOrigin,
        )
        return ProbeOutcome(
            mask = CompanionAlgorithmCheck.mask(verdict),
            reasons = CompanionAlgorithmCheck.reasons(verdict),
            verdict = verdict,
        )
    }

    fun observe(): Observation {
        return try {
            val googleKeys =
                AttestationAnalysis.anchorKeyEncodings(AttestationRoots.pinnedRoots)
            val softwareKeys =
                AttestationAnalysis.anchorKeyEncodings(SoftwareAttestationRoots.roots)

            val primary = attestedChain(PRIMARY_ALIAS, KeyProperties.KEY_ALGORITHM_EC)
                ?: return NOTHING_OBSERVED
            val primaryOrigin = originOf(primary, googleKeys, softwareKeys)
            val primaryHardwareBacked = hardwareBacked(primary)

            if (!CompanionAlgorithmCheck.worthAsking(primaryOrigin, primaryHardwareBacked)) {
                return Observation(
                    primaryChainLength = primary.size,
                    primaryOrigin = primaryOrigin,
                    primaryHardwareBacked = primaryHardwareBacked,
                    companionRequested = false,
                    companionChainLength = 0,
                    companionOrigin = CompanionAlgorithmCheck.RootOrigin.ABSENT,
                )
            }

            val companion = attestedChain(COMPANION_ALIAS, KeyProperties.KEY_ALGORITHM_RSA)
            Observation(
                primaryChainLength = primary.size,
                primaryOrigin = primaryOrigin,
                primaryHardwareBacked = primaryHardwareBacked,
                companionRequested = true,
                companionChainLength = companion?.size ?: 0,
                companionOrigin =
                    if (companion == null) CompanionAlgorithmCheck.RootOrigin.ABSENT
                    else originOf(companion, googleKeys, softwareKeys),
            )
        } catch (e: Throwable) {
            Log.w(TAG, "companion algorithm probe failed; failing clean", e)
            NOTHING_OBSERVED
        } finally {
            deleteQuietly(PRIMARY_ALIAS)
            deleteQuietly(COMPANION_ALIAS)
        }
    }

    /**
     * A chain whose links do not verify cannot be trusted to say what its own
     * root is, so it is classified as unrecognised rather than by its top
     * certificate. That also closes the obvious way to make this probe fire on
     * a stock device: appending a software root to a chain that was never
     * signed by it.
     */
    private fun originOf(
        chain: List<X509Certificate>,
        googleKeys: Set<List<Byte>>,
        softwareKeys: Set<List<Byte>>,
    ): CompanionAlgorithmCheck.RootOrigin {
        if (chain.isEmpty()) return CompanionAlgorithmCheck.RootOrigin.ABSENT
        if (AttestationAnalysis.chainSignaturesBroken(chain)) {
            return CompanionAlgorithmCheck.RootOrigin.UNRECOGNISED
        }
        return CompanionAlgorithmCheck.classifyRoot(chain.last(), googleKeys, softwareKeys)
    }

    private fun hardwareBacked(chain: List<X509Certificate>): Boolean {
        val ext = chain.firstOrNull()
            ?.getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
            ?: return false
        val level = AttestationAnalysis.parseAttestationSecurityLevel(ext)
        return level == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
            level == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
    }

    /** Null when the keystore would not serve an attested key of this algorithm. */
    private fun attestedChain(alias: String, algorithm: String): List<X509Certificate>? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

            val challenge = ByteArray(CHALLENGE_BYTES).also { SecureRandom().nextBytes(it) }
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .apply {
                    if (algorithm == KeyProperties.KEY_ALGORITHM_RSA) {
                        setKeySize(RSA_KEY_SIZE)
                        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    }
                }
                .build()

            KeyPairGenerator.getInstance(algorithm, ANDROID_KEYSTORE).apply {
                initialize(spec)
                generateKeyPair()
            }

            val raw = keyStore.getCertificateChain(alias) ?: return null
            raw.mapNotNull { it as? X509Certificate }.ifEmpty { null }
        } catch (e: Exception) {
            Log.i(TAG, "no attested $algorithm key available", e)
            null
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
        /**
         * Nothing was learned. Classified as unrecognised rather than absent so
         * the table's precondition closes and no verdict can be reached.
         */
        val NOTHING_OBSERVED = Observation(
            primaryChainLength = 0,
            primaryOrigin = CompanionAlgorithmCheck.RootOrigin.UNRECOGNISED,
            primaryHardwareBacked = false,
            companionRequested = false,
            companionChainLength = 0,
            companionOrigin = CompanionAlgorithmCheck.RootOrigin.ABSENT,
        )

        const val TAG = "CompanionAlgoProbe"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val PRIMARY_ALIAS = "pifd_companion_ec"
        const val COMPANION_ALIAS = "pifd_companion_rsa"
        const val CHALLENGE_BYTES = 32
        const val RSA_KEY_SIZE = 2048
    }
}
