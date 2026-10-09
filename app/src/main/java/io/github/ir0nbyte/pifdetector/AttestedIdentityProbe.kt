package io.github.ir0nbyte.pifdetector

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * Provokes two attestation records and hands their identifier tags to
 * [AttestedIdentity] to judge.
 *
 * One ordinary attestation, which asks for no identifier, and one with
 * `setDevicePropertiesAttestationIncluded(true)`, which asks for brand, device,
 * product, manufacturer and model. Two requests rather than one because the
 * interesting question is the difference between them: a record is allowed to
 * carry an identifier only if its request asked for one.
 *
 * Measured on both bench implementations before anything was written against
 * it. A Samsung TEE on API 34 and the AOSP software keystore on API 34 both
 * return an ordinary record with no identifier tag at all, and both refuse the
 * device-properties request with CANNOT_ATTEST_IDS, which is the answer
 * Tag.aidl requires from a device that cannot attest its identifiers. Neither
 * declares `android.software.device_id_attestation`.
 *
 * The accepted path is measured too, on a Pixel 7a that does declare it. The
 * request is accepted and the record carries tags 710, 711, 712, 716 and 717,
 * brand, device, product, manufacturer and model, in the hardwareEnforced list
 * at TrustedEnvironment level, with nothing in softwareEnforced and no
 * privileged identifier anywhere. So all three arms that judge an acceptance
 * are silent on a device that genuinely performs the attestation, which is the
 * check they shipped without.
 *
 * Two key generations per run, which is the cost of the arms being a comparison
 * between two requests rather than a reading of one. Measured on the bench
 * Samsung: BENCH identity=82ms boundary=105ms, so this probe is slightly
 * cheaper than the boundary one it sits beside. Folding the ordinary record
 * into another probe's key would save one generation and cost the arms their
 * independence, which is not a trade worth making at this price.
 *
 * Deliberately not implemented, and the reasons are worth keeping:
 *
 * - Comparing the attested values against `Build.BRAND` and friends.
 *   KeyGenParameterSpec's javadoc says the attested values "should be the same
 *   as" Build.BRAND, Build.DEVICE, Build.MANUFACTURER, Build.MODEL and
 *   Build.PRODUCT, and AndroidKeyStoreKeyPairGeneratorSpi CONTRADICTS IT: for
 *   each field it sends `Build.<X>_FOR_ATTESTATION` when that is neither empty
 *   nor "unknown", and that resolves through `ro.product.<x>_for_attestation`
 *   and `ro.product.vendor.<x>` rather than the property `Build.<X>` reads. So
 *   a multi-SKU or carrier-variant device can legitimately attest a value that
 *   differs from Build, which is the false positive the review of this spec
 *   blocked on. The value the framework actually sent is not knowable from an
 *   app either: every `Build.<X>_FOR_ATTESTATION` field is @hide and @TestApi.
 *   The bench confirms the properties are real rather than theoretical: this
 *   Samsung declares ro.product.device_for_attestation.
 * - Treating a refusal on a device that DOES declare device_id_attestation as a
 *   finding. A genuine device refuses when its remotely provisioned keys are
 *   exhausted and it is offline, and after destroyAttestationIds. That is
 *   inconclusive, not evidence.
 * - Gating the whole probe on `android.software.device_id_attestation`. That
 *   feature governs the privileged identifier subset; nothing documents it as
 *   governing device-properties attestation, and the javadoc for
 *   setDevicePropertiesAttestationIncluded names no feature at all. So its
 *   absence does not make an acceptance provably illegitimate, and gating on it
 *   would have skipped the probe entirely on every device on this bench.
 * - Requesting serial, IMEI or MEID. Those need READ_PRIVILEGED_PHONE_STATE and
 *   the hidden setAttestationIds, and asking for identifiers this app has no
 *   business holding is not something a detector should do. They are watched
 *   for in the answer instead.
 */
class AttestedIdentityProbe {

    fun probe(): AttestedIdentity.Verdict {
        return try {
            AttestedIdentity.evaluate(observe())
        } catch (e: Throwable) {
            // Fail open. A probe that cannot run must not accuse anyone.
            Log.w(TAG, "attested identity probe failed; failing safe", e)
            AttestedIdentity.Verdict(0, emptyList())
        }
    }

    /**
     * Public so a test can assert the arms actually ran. A probe that silently
     * skipped every arm would otherwise report clean for the wrong reason.
     */
    fun observe() = AttestedIdentity.Observation(
        plain = observePlain(),
        withProperties = observeWithProperties(),
    )

    private fun observePlain(): AttestedIdentity.RecordIds? {
        return try {
            wipe(ALIAS_PLAIN)
            readRecordIds(generate(ALIAS_PLAIN) { })
        } catch (e: Exception) {
            Log.d(TAG, "ordinary attestation unavailable on this device", e)
            null
        } finally {
            wipe(ALIAS_PLAIN)
        }
    }

    private fun observeWithProperties(): AttestedIdentity.PropertiesOutcome? {
        // setDevicePropertiesAttestationIncluded is API 31. Below it the
        // request cannot be expressed, so the arm reports nothing rather than
        // standing in for an answer the device was never asked for.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return try {
            wipe(ALIAS_PROPERTIES)
            val chain = generate(ALIAS_PROPERTIES) { builder ->
                builder.setDevicePropertiesAttestationIncluded(true)
            }
            AttestedIdentity.PropertiesOutcome(
                accepted = chain.isNotEmpty(),
                record = readRecordIds(chain),
            )
        } catch (e: Exception) {
            // The measured answer on both bench devices: ProviderException
            // wrapping KeyStoreException CANNOT_ATTEST_IDS, which Tag.aidl
            // requires from a device that cannot attest its identifiers. A
            // refusal for any other reason is equally not a finding, so the
            // cause is logged rather than classified.
            Log.d(TAG, "device-properties attestation refused", e)
            AttestedIdentity.PropertiesOutcome(accepted = false, record = null)
        } finally {
            wipe(ALIAS_PROPERTIES)
        }
    }

    /**
     * The identifier tags in a leaf's record, or null when there is no record
     * or its authorization lists did not parse. Both lists are required: they
     * share one member-count guard, so a half-read record would mean the guard
     * was bypassed on one side.
     */
    private fun readRecordIds(chain: List<X509Certificate>): AttestedIdentity.RecordIds? {
        val ext = chain.firstOrNull()?.getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
            ?: return null
        val hardware = AttestationAnalysis.hardwareEnforcedTags(ext) ?: return null
        val software = AttestationAnalysis.softwareEnforcedTags(ext) ?: return null
        return AttestedIdentity.RecordIds(
            hardwareEnforced = hardware.filterTo(HashSet()) { it in AttestedIdentity.ALL_ID_TAGS },
            softwareEnforced = software.filterTo(HashSet()) { it in AttestedIdentity.ALL_ID_TAGS },
            securityLevel = AttestationAnalysis.parseAttestationSecurityLevel(ext),
        )
    }

    private fun generate(
        alias: String,
        configure: (KeyGenParameterSpec.Builder) -> Unit,
    ): List<X509Certificate> {
        val challenge = ByteArray(CHALLENGE_BYTES).also { SecureRandom().nextBytes(it) }
        val builder = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
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
        const val TAG = "AttestedIdentity"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PLAIN = "pifd_identity_plain"
        const val ALIAS_PROPERTIES = "pifd_identity_properties"
        const val CHALLENGE_BYTES = 32
    }
}
