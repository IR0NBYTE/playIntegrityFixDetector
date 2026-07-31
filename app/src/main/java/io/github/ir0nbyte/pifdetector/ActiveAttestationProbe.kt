package io.github.ir0nbyte.pifdetector

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/*
 * Active key-attestation probe (DETECTION_ATTEST_FORGERY).
 *
 * KeyAttestationProbe asks for an ordinary attested key and inspects what comes
 * back. That is passive: it only sees a forgery if the spoofer chose to forge
 * for us. This probe instead ASKS FOR KEYS THAT ARE AWKWARD TO FORGE, so a
 * keybox spoofer has to either produce a chain that contradicts itself or
 * decline to forge at all. Nothing here matches a module name, a path, or a
 * library string, so renaming the module changes none of it.
 *
 * Two provocations, verified against TrickyStoreOSS and ForgeStore sources:
 *
 *  A. PURPOSE_ATTEST_KEY. TrickyStoreOSS decides whether to forge with
 *     `forceForge = needGenerate(callingUid) || hasDeviceIdAttestation ||
 *     kgp.purpose.contains(ATTEST_KEY) || attestationKeyDescriptor != null`.
 *     The ATTEST_KEY arm carries NO uid gate, so requesting one drags the
 *     forgery onto a caller that was never in the module's target list. That
 *     turns the existing root-anchoring check into a detection for the very
 *     common case where the detector simply is not a targeted package.
 *
 *  B. A key that REQUIRES user authentication, requested with a SHA-512 digest.
 *     Two independent contradictions can surface in the returned chain:
 *     the authorization list claiming NO_AUTH_REQUIRED for a key that plainly
 *     requires auth (see AttestationAnalysis.authRequirementContradiction), and
 *     a leaf signed with the digest we requested rather than the batch key's
 *     fixed SHA-256 (see leafSignatureTracksRequestedDigest).
 *
 * FAIL SAFE throughout, matching KeyAttestationProbe: an unsupported API level,
 * a device with no secure lock screen, attestation being absent, a short chain,
 * a parse failure, or any exception all return 0. Only a positively
 * self-contradictory or unanchored chain sets the bit, so a device that merely
 * cannot run a probe is never flagged.
 */
class ActiveAttestationProbe {

    private class Attested(val chain: List<X509Certificate>, val challenge: ByteArray)

    /*
     * Returns DETECTION_ATTEST_FORGERY when a provoked chain is proven forged,
     * else 0. Never throws.
     *
     * @param passiveProbeFlagged whether KeyAttestationProbe already reported an
     * anomaly for an ORDINARY attested key. When it did, an unanchored provoked
     * chain says nothing new -- a device with no hardware attestation at all
     * (emulator, AOSP build with a test root) fails anchoring for every key, and
     * reporting that twice would inflate one cause into two findings. Verified
     * on an API 36 emulator, whose chains root at "Droid Unregistered Device CA"
     * and so trip anchoring on both probes.
     *
     * The self-contradiction checks are NOT suppressed by this, because they
     * remain meaningful whatever the passive probe concluded.
     */
    fun probe(passiveProbeFlagged: Boolean): Int {
        return try {
            attestKeyProvocation(passiveProbeFlagged).takeIf { it != 0 }
                ?: authRequiredProvocation()
        } catch (e: Throwable) {
            Log.w(TAG, "active attestation probe failed; failing safe", e)
            0
        }
    }

    /*
     * Provocation A. PURPOSE_ATTEST_KEY exists only from API 31; below that we
     * cannot run this and return 0.
     *
     * A genuine device answers with a normal hardware chain that anchors to a
     * pinned Google root, so this is silent on clean hardware. Under a spoofer
     * the forced-forge path returns the keybox chain instead, which anchors
     * somewhere else (the shipped default is the public AOSP *software*
     * attestation keybox, whose root is not a hardware root at all).
     *
     * The anchoring check is what makes this specific: an ordinary key that
     * anchored fine while the ATTEST_KEY key does not is the forced-forge
     * signature. If the ordinary key already failed, anchoring here is not
     * evidence of anything new, so it is skipped.
     */
    private fun attestKeyProvocation(passiveProbeFlagged: Boolean): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return 0
        val attested = generate(ALIAS_ATTEST_KEY) { builder ->
            builder.setDigests(KeyProperties.DIGEST_SHA256)
        } ?: return 0

        val chain = attested.chain
        if (chain.isEmpty()) return 0

        if (AttestationAnalysis.isSelfSignedSingleCert(chain)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        val ext = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID) ?: return 0

        val challenge = AttestationAnalysis.parseAttestationChallenge(ext)
        if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        if (!passiveProbeFlagged &&
            !AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
        ) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        return 0
    }

    /*
     * Provocation B. Requires a secure lock screen; without one the generate
     * call throws and we return 0 rather than guessing.
     *
     * setUserAuthenticationParameters is API 30+; the older
     * setUserAuthenticationValidityDurationSeconds covers 23..29. Either way the
     * key genuinely requires authentication, which is the premise the
     * contradiction check rests on.
     */
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

        // The batch key's signing algorithm is fixed at provisioning and never
        // follows the attested key's digest. Checked before the extension parse
        // so it still applies if the extension is unreadable.
        if (AttestationAnalysis.leafSignatureTracksRequestedDigest(chain[0].sigAlgName)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        val ext = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID) ?: return 0

        val challenge = AttestationAnalysis.parseAttestationChallenge(ext)
        if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        // Sound only because we just demanded authentication for this key.
        if (AttestationAnalysis.authRequirementContradiction(ext)) {
            return DetectionResult.DETECTION_ATTEST_FORGERY
        }

        return 0
    }

    /*
     * Generate one attested key and hand back its chain. Returns null on any
     * failure -- unsupported parameters, no secure lock screen, attestation not
     * implemented -- so callers treat "could not ask" as "nothing to report".
     */
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
            // best-effort cleanup
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
