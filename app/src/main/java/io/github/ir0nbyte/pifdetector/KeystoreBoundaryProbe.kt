package io.github.ir0nbyte.pifdetector

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * Asks the keystore for request shapes the contract defines and a
 * reimplementation has to get right, then hands what came back to
 * [KeystoreBoundary] to judge.
 *
 * Two arms, both quoted from the KeyMint HAL:
 *
 * - No attestation challenge. IKeyMintDevice::generateKey returns a single
 *   self-signed certificate, and KeyMint returns that chain itself rather than
 *   the framework building one on its behalf, so the answer comes from the
 *   layer a simulator replaces.
 * - A challenge past the documented 128 byte maximum, which Tag.aidl says must
 *   draw INVALID_INPUT_LENGTH. Nothing in keystore2 enforces that limit, so
 *   again the rejection has to come from KeyMint.
 *
 * Deliberately not implemented, and the reasons are worth keeping:
 *
 * - The 0x8001 byte single update. It flagged a genuine handset whose OEM
 *   keystore mis-sizes the buffer, which is a defect in that device rather than
 *   evidence of spoofing.
 * - updateAad on a signing operation, and update after abort. Neither is
 *   reachable through public API; both need the keystore2 operation interface,
 *   so probing them would mean reflecting into non-public internals that shift
 *   between releases.
 * - A unique ID request. setUniqueIdIncluded is @hide, @TestApi and
 *   @UnsupportedAppUsage, so it is a system-app call and the hidden API
 *   denylist blocks reflection at it.
 * - An attestation challenge on a symmetric key. KeyGenParameterSpec's javadoc
 *   says generateKey() throws InvalidAlgorithmParameterException, and MEASURED
 *   BEHAVIOUR CONTRADICTS IT: both a Samsung TEE and the AOSP software keystore
 *   on API 34 accepted it with no exception at all. Implementing the documented
 *   rule would have flagged every device including a stock emulator, so the arm
 *   is dropped rather than shipped against a document nothing honours.
 */
class KeystoreBoundaryProbe {

    fun probe(): KeystoreBoundary.Verdict {
        return try {
            KeystoreBoundary.evaluate(observe())
        } catch (e: Throwable) {
            // Fail open. A probe that cannot run must not accuse anyone.
            Log.w(TAG, "keystore boundary probe failed; failing safe", e)
            KeystoreBoundary.Verdict(0, emptyList())
        }
    }

    /**
     * Public so a test can assert the arms actually ran. A probe that silently
     * skipped every arm would otherwise report clean for the wrong reason,
     * which is how this codebase previously shipped a dead obfuscation VM.
     */
    fun observe() = KeystoreBoundary.Observation(
        noChallenge = observeNoChallenge(),
        legalChallenge = observeChallenge(
            ALIAS_LEGAL, KeystoreBoundary.MAX_CHALLENGE_BYTES
        ),
        overLimitChallenge = observeChallenge(
            ALIAS_OVER_LIMIT, KeystoreBoundary.MAX_CHALLENGE_BYTES + 1
        ),
    )

    /**
     * One byte over the limit rather than wildly over it. A request for a
     * megabyte could plausibly be refused by something other than the length
     * rule, and then a pass would not mean the rule was enforced.
     */
    private fun observeChallenge(alias: String, size: Int): KeystoreBoundary.ChallengeOutcome? {
        return try {
            wipe(alias)
            val challenge = ByteArray(size).also { SecureRandom().nextBytes(it) }
            val chain = generate(alias) { builder ->
                builder.setDigests(KeyProperties.DIGEST_SHA256)
                builder.setAttestationChallenge(challenge)
            }
            val record = chain.firstOrNull()
                ?.getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
            val level = record?.let { AttestationAnalysis.parseAttestationSecurityLevel(it) }
            KeystoreBoundary.ChallengeOutcome(
                accepted = chain.isNotEmpty(),
                securityLevel = level,
            )
        } catch (e: Exception) {
            // The documented outcome for the over-limit arm, and the reason this
            // catch does not record an observation for it: a refusal is the
            // contract being honoured, so there is nothing to report.
            Log.d(TAG, "challenge of $size bytes refused", e)
            KeystoreBoundary.ChallengeOutcome(accepted = false, securityLevel = null)
        } finally {
            wipe(alias)
        }
    }

    private fun observeNoChallenge(): KeystoreBoundary.NoChallengeShape? {
        return try {
            wipe(ALIAS_NO_CHALLENGE)
            // PURPOSE_SIGN matters: the javadoc only promises a self-signed
            // certificate for a key that can sign one. Without it the
            // certificate carries a placeholder signature instead, and the
            // self-signed arm would be asserting something never promised.
            val chain = generate(ALIAS_NO_CHALLENGE) { builder ->
                builder.setDigests(KeyProperties.DIGEST_SHA256)
            }
            val leaf = chain.firstOrNull() ?: return null
            KeystoreBoundary.NoChallengeShape(
                selfSigned = leaf.issuerX500Principal == leaf.subjectX500Principal,
                carriesAttestationRecord =
                    leaf.getExtensionValue(AttestationAnalysis.ATTESTATION_OID) != null,
            )
        } catch (e: Exception) {
            Log.d(TAG, "no-challenge generation unavailable on this device", e)
            null
        } finally {
            wipe(ALIAS_NO_CHALLENGE)
        }
    }

    private fun generate(
        alias: String,
        configure: (KeyGenParameterSpec.Builder) -> Unit,
    ): List<X509Certificate> {
        val builder = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
        configure(builder)

        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(builder.build())
        generator.generateKeyPair()

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val raw = keyStore.getCertificateChain(alias) ?: return emptyList()
        return raw.mapNotNull { it as? X509Certificate }
    }

    private fun wipe(alias: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val TAG = "KeystoreBoundary"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_NO_CHALLENGE = "pifd_boundary_nochallenge"
        const val ALIAS_LEGAL = "pifd_boundary_legal"
        const val ALIAS_OVER_LIMIT = "pifd_boundary_overlimit"
    }
}
