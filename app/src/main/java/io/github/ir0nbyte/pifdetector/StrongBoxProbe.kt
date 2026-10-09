package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.crypto.KeyGenerator

/**
 * Asks the device three separate times whether it has StrongBox and hands the
 * answers to [StrongBoxCheck] to compare.
 *
 * The StrongBox request carries no attestation challenge, and that is the point
 * rather than an omission. A challenge drags remote key provisioning into the
 * call, and ResponseCode.aidl documents several ways that can fail on a
 * perfectly genuine device with no network, so a refusal would stop meaning
 * "there is no StrongBox here". Without a challenge the only thing being asked
 * is whether keystore2 has a KeyMint instance registered at that security
 * level, which is the question this probe wants answered.
 *
 * BENCH on the two KeyMint implementations the bench could run, a Samsung
 * SM-A065F TEE and the AOSP emulator, both on API 34 and neither declaring
 * strongbox_keystore: the StrongBox request is refused with
 * StrongBoxUnavailableException on both, the ordinary key is labelled
 * TrustedEnvironment on the Samsung and Software on the emulator, and no record
 * claims StrongBox in either of its two level fields. The AES arm reports
 * UNAVAILABLE on both, which is the outcome that matters here: the request was
 * well formed and reached the keystore, rather than being rejected locally by
 * the framework, so the arm is live and not dead. Cost measured at BENCH
 * strongbox=72ms on the Samsung and 90ms on the emulator, which is cheap
 * because both StrongBox requests land at getSecurityLevel before any key is
 * generated.
 *
 * The AES 192 arm is the constraint half of issue 7, built here because it is
 * the one candidate that survives primary source: the HAL is exclusive about
 * the size and the framework does not pre-empt the request. What this bench can
 * verify is that the request is well formed and reaches the keystore; what it
 * cannot is a genuine secure element refusing it, because no attached device
 * has one. See docs/COVERAGE.md.
 *
 * Specced in issue 7 and deliberately not built, with the reasons:
 *
 * - RSA 3072 in StrongBox. The spec called this the discriminating arm, and
 *   primary source does not support it: IKeyMintDevice.aidl says "StrongBox
 *   IKeyMintDevice implementations must support 2048", which is a floor on what
 *   must work and not a ceiling on what may. A StrongBox that also supports
 *   3072 violates nothing, so flagging it would be guessing.
 * - A non-P-256 curve in StrongBox. Here the HAL is exclusive, "StrongBox
 *   implementations must support P_256 and no other curves", but the request
 *   never reaches KeyMint: checkValidKeySize in
 *   AndroidKeyStoreKeyPairGeneratorSpi throws InvalidAlgorithmParameterException
 *   for a StrongBox EC key of any size but 256, and separately for curve 25519.
 *   The real framework refuses it on a spoofed device exactly as it does on a
 *   genuine one, so the arm cannot discriminate.
 * - The keygen latency floor. Ruled out by the review before this pass, and
 *   docs/DETECTION.md gives the general reason timing is not used here.
 * - The two security levels one record states having to match each other. The
 *   review ruled this out on the grounds that nothing requires it, and primary
 *   source now contradicts that for one schema: from attestation version 400
 *   KeyCreationResult.aidl says attestationSecurityLevel "Must match
 *   keymintSecurityLevel" and repeats the requirement under the other field,
 *   where schemas 100 through 300 describe both as "See below" and state no
 *   relationship. It is unbuilt because no attached device emits a 400 record,
 *   so the clean path cannot be witnessed even once, and because a record
 *   forged field by field would be given two matching levels anyway. Both
 *   levels are still read, since either one naming StrongBox is a claim.
 */
class StrongBoxProbe {

    fun probe(context: Context): StrongBoxCheck.Verdict {
        return try {
            StrongBoxCheck.evaluate(observe(context))
        } catch (e: Throwable) {
            // Fail open. A probe that cannot run must not accuse anyone.
            Log.w(TAG, "strongbox probe failed; failing safe", e)
            StrongBoxCheck.Verdict(0, emptyList())
        }
    }

    /**
     * Public so a test can assert the arms actually ran. A probe that silently
     * skipped every arm would otherwise report clean for the wrong reason,
     * which is how this codebase previously shipped a dead obfuscation VM.
     */
    fun observe(context: Context): StrongBoxCheck.Observation {
        val ordinary = observeOrdinaryKey()
        return StrongBoxCheck.Observation(
            featureDeclared = declaresStrongBox(context),
            availability = observeAvailability(),
            ordinaryKeyLevel = ordinary?.level,
            ordinaryRecord = ordinary?.record,
            aes192 = observeAes192(),
        )
    }

    private class OrdinaryKey(
        val level: Int?,
        val record: StrongBoxCheck.Record?,
    )

    /**
     * Null rather than false when PackageManager cannot be reached, so an arm
     * that could not ask is never read as an arm that got an answer.
     */
    private fun declaresStrongBox(context: Context): Boolean? {
        return try {
            context.packageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)
        } catch (e: Throwable) {
            Log.d(TAG, "feature list unavailable", e)
            null
        }
    }

    private fun observeAvailability(): StrongBoxCheck.Availability? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return StrongBoxArm().observe()
    }

    /**
     * Attempted on every device, judged on almost none.
     *
     * Running it even where there is no StrongBox is what proves the request is
     * well formed and reaches the keystore, which is the only part of this arm
     * a bench without a secure element can verify. A device with no StrongBox
     * answers UNAVAILABLE, and [StrongBoxCheck] judges nothing in that case.
     */
    private fun observeAes192(): StrongBoxCheck.AesOutcome? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return StrongBoxAesArm().observe()
    }

    /**
     * An ordinary key, which is to say one that asked for nothing unusual: no
     * StrongBox, and a challenge only so the record exists to be read.
     *
     * The challenge is retried away on failure rather than giving up. Arm one
     * reads the keystore's own label on the key and needs no record at all, so
     * a device that cannot attest right now should still have its label read.
     */
    private fun observeOrdinaryKey(): OrdinaryKey? {
        val attested = generateOrdinary(withChallenge = true)
        if (attested != null) return attested
        return generateOrdinary(withChallenge = false)
    }

    private fun generateOrdinary(withChallenge: Boolean): OrdinaryKey? {
        return try {
            wipe(ALIAS_ORDINARY)
            val chain = generate(ALIAS_ORDINARY) { builder ->
                builder.setDigests(KeyProperties.DIGEST_SHA256)
                if (withChallenge) {
                    val challenge = ByteArray(CHALLENGE_BYTES)
                        .also { SecureRandom().nextBytes(it) }
                    builder.setAttestationChallenge(challenge)
                }
            }
            OrdinaryKey(
                level = readKeyLevel(ALIAS_ORDINARY),
                record = readRecord(chain),
            )
        } catch (e: Exception) {
            Log.d(TAG, "ordinary key with challenge=$withChallenge unavailable", e)
            null
        } finally {
            wipe(ALIAS_ORDINARY)
        }
    }

    /**
     * What the keystore itself says about where the key lives, which is a
     * separate statement from anything in the attestation record.
     *
     * Only readable from API 31. The older isInsideSecureHardware is a boolean
     * and cannot tell a TEE from a secure element, so below 31 this stays null
     * instead of being approximated.
     */
    private fun readKeyLevel(alias: String): Int? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = keyStore.getKey(alias, null) as? PrivateKey ?: return null
            KeyLevelArm().read(key)
        } catch (e: Exception) {
            Log.d(TAG, "key security level unreadable", e)
            null
        }
    }

    private fun readRecord(chain: List<X509Certificate>): StrongBoxCheck.Record? {
        val ext = chain.firstOrNull()?.getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
            ?: return null
        return StrongBoxCheck.Record(
            attestationLevel = AttestationAnalysis.parseAttestationSecurityLevel(ext),
            keyMintLevel = AttestationAnalysis.parseKeyMintSecurityLevel(ext),
        )
    }

    /**
     * Every StrongBox API reference this probe makes, in a class that is only
     * loaded on API 28 or later.
     *
     * The isolation is not decoration. A catch clause names a real class, and
     * ART resolves the exception types of a method when it verifies the class
     * that holds it, so a catch on StrongBoxUnavailableException sitting in an
     * ungated class risks a verification failure on API 24 through 27 rather
     * than the quiet skip the SDK check was supposed to produce. The int
     * constants elsewhere in this codebase do not have that problem, which is
     * why they are gated in place and this is not.
     */
    @RequiresApi(Build.VERSION_CODES.P)
    private inner class StrongBoxArm {
        fun observe(): StrongBoxCheck.Availability {
            return try {
                wipe(ALIAS_STRONGBOX)
                val chain = generate(ALIAS_STRONGBOX) { builder ->
                    builder.setDigests(KeyProperties.DIGEST_SHA256)
                    builder.setIsStrongBoxBacked(true)
                }
                // A served request that somehow produced no certificate is not
                // evidence either way, so it does not claim StrongBox exists.
                if (chain.isEmpty()) {
                    StrongBoxCheck.Availability.INCONCLUSIVE
                } else {
                    StrongBoxCheck.Availability.SERVED
                }
            } catch (e: StrongBoxUnavailableException) {
                // The one keystore2 error the framework maps to this type is
                // HARDWARE_TYPE_UNAVAILABLE, which service.rs returns when no
                // KeyMint instance is registered at that security level. That
                // makes this the only failure that means "there is no
                // StrongBox here".
                Log.d(TAG, "no StrongBox instance on this device", e)
                StrongBoxCheck.Availability.UNAVAILABLE
            } catch (e: Exception) {
                Log.d(TAG, "StrongBox request failed for another reason", e)
                StrongBoxCheck.Availability.INCONCLUSIVE
            } finally {
                wipe(ALIAS_STRONGBOX)
            }
        }
    }

    /**
     * The AES size restriction, in its own gated class for the same reason as
     * [StrongBoxArm]: it catches StrongBoxUnavailableException.
     */
    @RequiresApi(Build.VERSION_CODES.P)
    private inner class StrongBoxAesArm {
        fun observe(): StrongBoxCheck.AesOutcome {
            return try {
                wipe(ALIAS_AES)
                generateAes(ALIAS_AES, StrongBoxCheck.AES_FORBIDDEN_SIZE_BITS)
                StrongBoxCheck.AesOutcome.ACCEPTED
            } catch (e: StrongBoxUnavailableException) {
                // No secure element, so the size was never the question.
                Log.d(TAG, "no StrongBox instance for the AES arm", e)
                StrongBoxCheck.AesOutcome.UNAVAILABLE
            } catch (e: InvalidAlgorithmParameterException) {
                // The framework rejected the parameter spec locally, so KeyMint
                // never saw it. That is a defect in this probe rather than an
                // answer from the device, and reporting it as a refusal would
                // leave the arm dead and silent.
                Log.w(TAG, "the AES arm's own request was rejected; arm did not run", e)
                StrongBoxCheck.AesOutcome.NOT_ATTEMPTED
            } catch (e: Exception) {
                // What a genuine StrongBox does: UNSUPPORTED_KEY_SIZE, which
                // the framework surfaces as a ProviderException.
                Log.d(TAG, "StrongBox refused a 192 bit AES key", e)
                StrongBoxCheck.AesOutcome.REFUSED
            } finally {
                wipe(ALIAS_AES)
            }
        }

        private fun generateAes(alias: String, sizeBits: Int) {
            val spec = KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setKeySize(sizeBits)
                .setIsStrongBoxBacked(true)
                .build()

            val generator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            generator.init(spec)
            generator.generateKey()
        }
    }

    /** KeyInfo.getSecurityLevel arrived in API 31, so it is isolated too. */
    @RequiresApi(Build.VERSION_CODES.S)
    private inner class KeyLevelArm {
        fun read(key: PrivateKey): Int? {
            val factory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) ?: return null
            return info.securityLevel
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
        const val TAG = "StrongBoxProbe"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_STRONGBOX = "pifd_strongbox_request"
        const val ALIAS_ORDINARY = "pifd_strongbox_ordinary"
        const val ALIAS_AES = "pifd_strongbox_aes"

        /** PackageManager.FEATURE_STRONGBOX_KEYSTORE, a literal because minSdk is 24. */
        const val FEATURE_STRONGBOX_KEYSTORE = "android.hardware.strongbox_keystore"

        /** Well inside the documented 128 byte maximum. */
        const val CHALLENGE_BYTES = 32
    }
}
