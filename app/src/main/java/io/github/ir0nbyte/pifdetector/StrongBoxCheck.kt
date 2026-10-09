package io.github.ir0nbyte.pifdetector

/**
 * The decision table for what the device says about StrongBox.
 *
 * StrongBox is a separate, certified secure processor rather than a mode of the
 * main one. IKeyMintDevice.aidl calls them "completely separate, purpose-built
 * and certified secure CPUs", gives embedded Secure Elements as the example,
 * and requires CDD 9.11.2 to qualify. A device either has that part or it does
 * not, which makes it one of the few claims a property spoofer cannot arrange.
 *
 * Three places on one device state whether StrongBox is there, and this table
 * asks whether they agree, then asks a fourth question of a device that does
 * have one: whether it refuses what a real secure element has to refuse.
 *
 * The three statements are:
 *
 * - keystore2, when asked for a StrongBox key. service.rs answers
 *   HARDWARE_TYPE_UNAVAILABLE when no KeyMint instance is registered at that
 *   security level, and AndroidKeyStoreKeyPairGeneratorSpi turns that one error
 *   into StrongBoxUnavailableException. There is no hasSystemFeature test
 *   anywhere in the generate path, so this answer comes from the registered HAL
 *   instances rather than from a line of Java that a reimplementation also
 *   runs.
 * - the keystore's own label on an ordinary key, KeyInfo.getSecurityLevel.
 * - the attestation record, which states a security level twice.
 *
 * The first arms need no reading of any document. If keystore2 says no
 * StrongBox instance exists on this device, then nothing on this device may
 * come back labelled StrongBox, because the label would name a thing the
 * keystore has just said it does not have. A device that does both has
 * contradicted itself in one run.
 *
 * What is deliberately not a finding is a refusal. A device that declares
 * StrongBox and then fails to serve a key may be out of remotely provisioned
 * keys with no network, which ResponseCode.aidl documents as
 * OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY, so the honest reading of a refusal
 * is "could not tell" rather than "lying". Only claiming more than the device
 * has is reported.
 *
 * Deliberately Android-free and side-effect-free so the whole table is unit
 * testable. [StrongBoxProbe] does the generating and hands the results here.
 *
 * Every arm lands on DETECTION_ATTEST_FORGERY, as the other keystore probes do:
 * the finding is that the record or the label contradicts something the
 * platform guarantees.
 */
object StrongBoxCheck {

    /**
     * keystore2's answer to "is there a StrongBox KeyMint instance here".
     *
     * [UNAVAILABLE] is reserved for StrongBoxUnavailableException specifically,
     * which the framework raises for exactly one keystore2 error. Every other
     * failure is [INCONCLUSIVE], because a key that failed to generate for some
     * other reason says nothing about whether the hardware exists. Keeping
     * those apart is the whole reason the probe catches a narrow exception type
     * rather than Exception.
     */
    enum class Availability { SERVED, UNAVAILABLE, INCONCLUSIVE }

    /**
     * What happened when StrongBox was asked for a 192 bit AES key.
     *
     * IKeyMintDevice.aidl is exclusive about this one: "STRONGBOX
     * IKeyMintDevices must only support 128 and 256-bit keys". Unlike the EC
     * restrictions, nothing in the framework pre-empts it.
     * AndroidKeyStoreKeyGeneratorSpi permits 128, 192 and 256 with no StrongBox
     * branch, so the request reaches KeyMint and the refusal has to come from
     * there.
     *
     * [NOT_ATTEMPTED] is kept apart from [UNAVAILABLE] deliberately. If the
     * request were malformed, the framework would reject the parameter spec
     * before the keystore ever saw it, and recording that as a refusal would
     * leave a dead arm reporting clean forever. That is the failure this
     * codebase keeps auditing for, so a spec rejected locally is
     * [NOT_ATTEMPTED] and the instrumented test asserts against it.
     */
    enum class AesOutcome { ACCEPTED, REFUSED, UNAVAILABLE, NOT_ATTEMPTED }

    /**
     * The one AES size a KeyMint StrongBox must not support. 128 and 256 are
     * the two it must, so 192 is the only value in the gap. A wildly invalid
     * size would prove nothing, because something other than the StrongBox rule
     * could refuse it.
     */
    const val AES_FORBIDDEN_SIZE_BITS = 192

    /**
     * The strongbox_keystore feature version from which the AES size
     * restriction exists at all.
     *
     * MEASURED, and the measurement is the reason this gate is here. The
     * exclusive sentence, "STRONGBOX IKeyMintDevices must only support 128 and
     * 256-bit keys", appears in IKeyMintDevice.aidl and in no earlier HAL. The
     * Keymaster 4.0 document that preceded it lists AES as "128 and 256-bit
     * keys" with no StrongBox clause of any kind, so it never forbade 192 to a
     * secure element. A stock, locked Samsung SM-G780G declaring
     * strongbox_keystore=4 accepts a 192 bit StrongBox AES key, and it is
     * entitled to: it implements Keymaster 4.0, not KeyMint.
     *
     * PackageManager's javadoc gives the version ladder as 40 and 41 for the
     * Keymaster generations and 100 upward for KeyMint, 100 being where
     * hardware ECDH and app-generated attestation keys arrive. So 100 is the
     * first version whose HAL carries the restriction.
     *
     * A device that declares no version reads as 0 and is never judged, which
     * is the safe direction: the javadoc warns the version may be unset on
     * anything launched before Android 12.
     */
    const val STRONGBOX_FEATURE_VERSION_KEYMINT_1 = 100

    /**
     * The two security levels one attestation record states.
     *
     * Both are read because either one naming StrongBox is the record making
     * the claim. attestationSecurityLevel is the level the attested key is
     * stored at and keyMintSecurityLevel is the level of the IKeyMintDevice
     * that produced the record, so they are separate statements and a forged
     * record has to get both right.
     */
    data class Record(
        val attestationLevel: Int?,
        val keyMintLevel: Int?,
    ) {
        /** Whether either stated level names StrongBox. */
        val claimsStrongBox: Boolean
            get() = attestationLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX ||
                keyMintLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
    }

    /**
     * A null field means the question could not be asked or its answer could
     * not be read on this device, which is never a finding.
     *
     * [featureDeclared] is hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE).
     * [availability] is absent below API 28, where setIsStrongBoxBacked does
     * not exist. [ordinaryKeyLevel] is KeyInfo.getSecurityLevel, absent below
     * API 31 where the accessor does not exist and the older
     * isInsideSecureHardware cannot tell a TEE from a secure element.
     */
    data class Observation(
        val featureDeclared: Boolean? = null,
        val strongBoxFeatureVersion: Int? = null,
        val availability: Availability? = null,
        val ordinaryKeyLevel: Int? = null,
        val ordinaryRecord: Record? = null,
        val aes192: AesOutcome? = null,
    )

    data class Verdict(val mask: Int, val reasons: List<Int>) {
        val isFinding: Boolean get() = mask != 0
    }

    fun evaluate(observation: Observation): Verdict {
        val reasons = ArrayList<Int>(4)

        // keystore2 has just said there is no StrongBox instance on this
        // device. Both arms below are the device disagreeing with itself, so
        // neither rests on a reading of any specification.
        if (observation.availability == Availability.UNAVAILABLE) {
            if (observation.ordinaryKeyLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX) {
                reasons.add(REASON_KEY_IN_ABSENT_STRONGBOX)
            }
            if (observation.ordinaryRecord?.claimsStrongBox == true) {
                reasons.add(REASON_RECORD_CLAIMS_ABSENT_STRONGBOX)
            }
        }

        // The other direction, and the only arm here that leans on the feature
        // list being honest: the keystore served a StrongBox key on a device
        // whose own feature declaration says it has no StrongBox. Reported
        // because CTS treats that declaration as the authority for whether the
        // hardware is there, and recorded in docs/COVERAGE.md with its false
        // positive vector, since an OEM can ship the HAL instance and forget
        // the feature entry.
        if (observation.availability == Availability.SERVED &&
            observation.featureDeclared == false
        ) {
            reasons.add(REASON_UNDECLARED_STRONGBOX)
        }

        // The constraint arm, and the only one here that asks a StrongBox to
        // refuse something rather than asking it to exist. Gated twice. On the
        // keystore having actually served a StrongBox key, because on a device
        // with no secure element the AES request is turned away for that reason
        // and says nothing about key sizes. And on the secure element being a
        // KeyMint one, because the restriction does not exist before KeyMint
        // and a genuine Keymaster 4.0 StrongBox on the bench accepts the size:
        // see STRONGBOX_FEATURE_VERSION_KEYMINT_1. Phrased as acceptance being
        // the finding, never refusal, which is what a conforming StrongBox
        // does.
        if (observation.availability == Availability.SERVED &&
            observation.aes192 == AesOutcome.ACCEPTED &&
            (observation.strongBoxFeatureVersion ?: 0) >= STRONGBOX_FEATURE_VERSION_KEYMINT_1
        ) {
            reasons.add(REASON_STRONGBOX_TOOK_AES_192)
        }

        val mask = if (reasons.isEmpty()) 0 else DetectionResult.DETECTION_ATTEST_FORGERY
        return Verdict(mask, reasons)
    }

    const val REASON_KEY_IN_ABSENT_STRONGBOX = 1109
    const val REASON_RECORD_CLAIMS_ABSENT_STRONGBOX = 1110
    const val REASON_UNDECLARED_STRONGBOX = 1111
    const val REASON_STRONGBOX_TOOK_AES_192 = 1112

    /**
     * Every code this probe can emit. [ReasonCodesSyncTest] unions this with
     * the other producers, so a code with no producer and a producer with no
     * text both fail the build.
     */
    val REASON_CODES: Set<Int> = setOf(
        REASON_KEY_IN_ABSENT_STRONGBOX,
        REASON_RECORD_CLAIMS_ABSENT_STRONGBOX,
        REASON_UNDECLARED_STRONGBOX,
        REASON_STRONGBOX_TOOK_AES_192,
    )
}
