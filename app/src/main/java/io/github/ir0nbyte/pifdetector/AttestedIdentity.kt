package io.github.ir0nbyte.pifdetector

/**
 * The decision table for device-properties attestation.
 *
 * `setDevicePropertiesAttestationIncluded` asks KeyMint to put brand, device,
 * product, manufacturer and model into the attestation record, signed by the
 * secure environment. Those are the only renderings of a device's identity that
 * a global property spoofer cannot rewrite, which is why a simulator has to
 * forge them rather than pass them through.
 *
 * What this table judges is not the values. It is whether an identifier appears
 * in a record whose request never asked for one.
 *
 * Tag.aidl says of every one of these tags, in the same words: "This field must
 * be set only when requesting attestation of the device's identifiers." That
 * sentence is addressed to the caller rather than to the device, so the rule
 * read here is the inference from it: an identifier tag reaches a record only
 * because the request carried it, and for an ordinary attestation no layer
 * carried one. AndroidKeyStoreKeyPairGeneratorSpi adds these tags only when
 * setDevicePropertiesAttestationIncluded is set, and keystore2 forwards what it
 * is given, so an identifier in an ordinary record was volunteered by the
 * keystore itself. An OEM KeyMint that populates the identifier block
 * unconditionally would be reported by this arm, which is recorded as its
 * false positive vector in docs/COVERAGE.md.
 *
 * The privileged half needs no such inference. Reaching serial, IMEI or MEID
 * takes READ_PRIVILEGED_PHONE_STATE and the hidden setAttestationIds, so an app
 * holding none of those receiving one back is a platform violation however the
 * sentence above is read.
 *
 * The remaining arms judge the keystore against its own answer rather than
 * against a document: accepting the request and then attesting nothing, or
 * attesting identifiers that the secure environment which signed the record did
 * not vouch for.
 *
 * Deliberately Android-free and side-effect-free so the whole table is unit
 * testable. [AttestedIdentityProbe] does the generating and hands the results
 * here.
 *
 * Every arm lands on DETECTION_ATTEST_FORGERY, for the same reason the boundary
 * probes do: the finding is that the record contradicts a platform guarantee.
 * The reason codes are what tell a report which contradiction was seen.
 */
object AttestedIdentity {

    // Tag numbers read out of Tag.aidl rather than recalled. All nine are
    // OCTET STRING members of AuthorizationList in the KeyDescription schema
    // published in KeyCreationResult.aidl.
    const val TAG_ID_BRAND = 710
    const val TAG_ID_DEVICE = 711
    const val TAG_ID_PRODUCT = 712
    const val TAG_ID_SERIAL = 713
    const val TAG_ID_IMEI = 714
    const val TAG_ID_MEID = 715
    const val TAG_ID_MANUFACTURER = 716
    const val TAG_ID_MODEL = 717
    const val TAG_ID_SECOND_IMEI = 723

    /**
     * Exactly what `setDevicePropertiesAttestationIncluded(true)` makes the
     * framework request, from AndroidKeyStoreKeyPairGeneratorSpi: brand,
     * device, product, manufacturer, model, and nothing else.
     */
    val DEVICE_PROPERTY_TAGS: Set<Int> = setOf(
        TAG_ID_BRAND, TAG_ID_DEVICE, TAG_ID_PRODUCT, TAG_ID_MANUFACTURER, TAG_ID_MODEL,
    )

    /**
     * The subset an ordinary app may neither request nor receive. Reaching
     * these needs READ_PRIVILEGED_PHONE_STATE and the hidden setAttestationIds,
     * so one of them in a record this app provoked was put there by the
     * keystore on its own initiative.
     */
    val PRIVILEGED_TAGS: Set<Int> = setOf(
        TAG_ID_SERIAL, TAG_ID_IMEI, TAG_ID_MEID, TAG_ID_SECOND_IMEI,
    )

    /** Every identifier tag the schema defines, for filtering a record down. */
    val ALL_ID_TAGS: Set<Int> = DEVICE_PROPERTY_TAGS + PRIVILEGED_TAGS

    /**
     * The identifier tags one record carries, split by the list that held them.
     *
     * The split is load bearing. KeyCreationResult.aidl defines
     * softwareEnforced as "the authorization tags enforced by the Android
     * system" and hardwareEnforced as those "enforced by a secure
     * environment", so an identifier that sits only in the software list was
     * never vouched for by the part of the device that cannot be rewritten.
     *
     * Built only from a record whose authorization lists both parsed. An
     * unparseable record yields null rather than an empty set, because "no
     * identifier" and "could not tell" must not reach the table as the same
     * observation: KeyDescription schema versions before the eight-member
     * layout do not parse here, and those are the oldest devices this app
     * supports.
     */
    data class RecordIds(
        val hardwareEnforced: Set<Int>,
        val softwareEnforced: Set<Int>,
        val securityLevel: Int?,
    ) {
        val all: Set<Int> get() = hardwareEnforced + softwareEnforced

        val vouchedBySecureEnvironment: Boolean
            get() = securityLevel == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                securityLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
    }

    /** What the keystore did when asked to attest the device properties. */
    data class PropertiesOutcome(
        val accepted: Boolean,
        val record: RecordIds?,
    )

    /**
     * A null field means the request could not be made or its answer could not
     * be read on this device, which is never a finding.
     *
     * [plain] is the record from an ordinary attestation request, which asked
     * for no identifier at all. [withProperties] is the device-properties
     * request, absent below API 31 where the setter does not exist.
     */
    data class Observation(
        val plain: RecordIds? = null,
        val withProperties: PropertiesOutcome? = null,
    )

    data class Verdict(val mask: Int, val reasons: List<Int>) {
        val isFinding: Boolean get() = mask != 0
    }

    fun evaluate(observation: Observation): Verdict {
        val reasons = ArrayList<Int>(3)

        // Nothing in the request carried an identifier, so nothing legitimate
        // put one in the answer. This is the arm a keystore that fills the
        // identifier block unconditionally cannot pass, and it needs no opinion
        // about whether the values themselves are right.
        val plain = observation.plain
        if (plain != null && plain.all.any { it in DEVICE_PROPERTY_TAGS }) {
            reasons.add(REASON_UNREQUESTED_ID)
        }

        // Checked across both records, and deliberately without asking whether
        // the second request was accepted. The other arms ask what the keystore
        // answered, so a failed request tells them nothing. This one asks what
        // this app was handed, and a privileged identifier that reached a record
        // reached it whatever the call reported. The probe never produces a
        // refusal carrying a record, so this is about keeping the two questions
        // distinct rather than about a shape seen in the wild.
        val carriesPrivileged = listOfNotNull(plain, observation.withProperties?.record)
            .any { record -> record.all.any { it in PRIVILEGED_TAGS } }
        if (carriesPrivileged) reasons.add(REASON_PRIVILEGED_ID)

        val outcome = observation.withProperties
        if (outcome != null && outcome.accepted) {
            val record = outcome.record
            // A refusal is the contract's own answer for a device that cannot
            // attest its identifiers, so only an acceptance is judged here. An
            // acceptance whose record could not be read is left alone: see
            // RecordIds on why that is not treated as "no identifier".
            if (record != null) {
                if (record.all.none { it in DEVICE_PROPERTY_TAGS }) {
                    reasons.add(REASON_ACCEPTED_WITHOUT_IDS)
                } else if (
                    record.vouchedBySecureEnvironment &&
                    record.hardwareEnforced.none { it in DEVICE_PROPERTY_TAGS }
                ) {
                    // The record claims a secure environment produced it, yet
                    // the identifiers sit where the Android system puts its own
                    // entries. On a software-level record that is simply where
                    // everything legitimately sits, which is why the level is
                    // part of the condition rather than an afterthought.
                    reasons.add(REASON_IDS_NOT_VOUCHED)
                }
            }
        }

        val mask = if (reasons.isEmpty()) 0 else DetectionResult.DETECTION_ATTEST_FORGERY
        return Verdict(mask, reasons)
    }

    const val REASON_UNREQUESTED_ID = 1105
    const val REASON_PRIVILEGED_ID = 1106
    const val REASON_ACCEPTED_WITHOUT_IDS = 1107
    const val REASON_IDS_NOT_VOUCHED = 1108

    /**
     * Every code this probe can emit. [ReasonCodesSyncTest] unions this with
     * the other producers, so a code with no producer and a producer with no
     * text both fail the build.
     */
    val REASON_CODES: Set<Int> = setOf(
        REASON_UNREQUESTED_ID,
        REASON_PRIVILEGED_ID,
        REASON_ACCEPTED_WITHOUT_IDS,
        REASON_IDS_NOT_VOUCHED,
    )
}
