package io.github.ir0nbyte.pifdetector

/**
 * Structural checks on the two authorization lists.
 *
 * Tag ORDER is deliberately not a finding. A genuine retail Motorola Edge
 * (2022) emits its hardware-enforced list descending across several
 * attestation-ID tags, with a KeyMint 1.0 record that anchors to the pinned
 * Google root and passes Google's own verifier. Both that verifier and CTS read
 * the list by switching on each tag number in a loop, so neither depends on
 * order, and roughly one record in fifty from the only published corpus
 * violates it. Order is reported on the row and sets no bit.
 *
 * What is a finding is a shape no one-field-per-tag encoder can produce: the
 * same schema tag repeated inside one list, a tag the schema says must never be
 * attested, or a tag in the list it cannot belong to.
 */
object RecordShape {

    /** Every tag number the published AuthorizationList schema defines. */
    private val SCHEMA_AUTHZ_TAGS = setOf(
        1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 200, 203, 303, 305, 400, 401, 402, 405,
        502, 503, 504, 505, 506, 507, 508, 509, 701, 702, 704, 705, 706, 709,
        710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 723, 724,
    )

    /**
     * Tags that can only be enforced by the secure implementation, so a
     * hardware-backed record cannot carry them in the software list.
     *
     * noAuthRequired (503) is deliberately absent. CTS requires only that it
     * appear in exactly one of the two lists, so a TEE record carrying it in
     * the software list is conformant, and the probe's own key always sets it,
     * which would have made it the highest-exposure member of this set.
     */
    private val HARDWARE_ONLY_TAGS = setOf(
        1, 2, 3, 4, 5, 6, 10, 504, 505, 702, 704, 705, 706, 718, 719,
    )

    /** Tags the platform rather than the TA records. */
    private val SOFTWARE_ONLY_TAGS = setOf(506, 701, 709)

    /**
     * Tags the schema says must never be attested at all. Narrow on purpose:
     * 501 carries "must not be hardware-enforced" and is skipped by every AOSP
     * encoder, and 700 is "must never appear in KeyCharacteristics". Tags 600,
     * 601 and 502 were dropped because they are schema-legal for the Keymaster
     * era and AOSP's own legacy encoder still has emit paths for them.
     */
    private val NEVER_ATTESTED_TAGS = setOf(501, 700)

    /** Attestation IDs, exempt from the order readout as members and neighbours. */
    private val ATTESTATION_ID_TAGS = setOf(710, 711, 712, 713, 714, 715, 716, 717, 723)

    data class Verdict(
        val duplicateSchemaTag: Boolean = false,
        val neverAttestedTagPresent: Boolean = false,
        val hardwareOnlyTagInSoftwareList: Boolean = false,
        val softwareOnlyTagInHardwareList: Boolean = false,
        /** Reported only. Genuine devices emit out-of-order lists. */
        val listOutOfOrder: Boolean = false,
        /** Reported only. A vendor-private or future tag is not something to judge. */
        val unknownTagPresent: Boolean = false,
        val offendingTags: List<Int> = emptyList(),
        val evaluated: Boolean = true,
    ) {
        val isFinding: Boolean get() =
            duplicateSchemaTag || neverAttestedTagPresent ||
                hardwareOnlyTagInSoftwareList || softwareOnlyTagInHardwareList

        companion object {
            val NONE = Verdict()
            val NOT_EVALUATED = Verdict(evaluated = false)
        }
    }

    /**
     * @param attestationVersion gates the whole check at Keymaster 4.0 and
     *   later. Versions 1 and 2 predate the list contract this leans on.
     * @param haveTrustAnchors false means the pinned set is empty, in which case
     *   anchoring was vacuous and nothing here may speak.
     */
    fun evaluate(
        hardwareTags: List<Int>?,
        softwareTags: List<Int>?,
        attestationVersion: Int?,
        hardwareBacked: Boolean,
        anchored: Boolean,
        haveTrustAnchors: Boolean,
    ): Verdict {
        if (hardwareTags == null || softwareTags == null) return Verdict.NOT_EVALUATED
        if (!anchored || !haveTrustAnchors || !hardwareBacked) return Verdict.NOT_EVALUATED
        if (attestationVersion == null ||
            attestationVersion < AttestationAnalysis.ATTESTATION_VERSION_KEYMASTER_4
        ) {
            return Verdict.NOT_EVALUATED
        }

        val offenders = LinkedHashSet<Int>()

        // Duplicates WITHIN a list, among known schema tags only. One field per
        // tag makes a repeat structurally impossible inside one authorization
        // list, but the same tag appearing once in each list is a different
        // thing and is not judged here: a repeated vendor-private tag is not
        // something this project can reason about either.
        val dupes = (duplicatesIn(hardwareTags) + duplicatesIn(softwareTags)).toSet()
        offenders.addAll(dupes)

        val never = (hardwareTags + softwareTags).filter { it in NEVER_ATTESTED_TAGS }
        offenders.addAll(never)

        val hwInSw = softwareTags.filter { it in HARDWARE_ONLY_TAGS }
        offenders.addAll(hwInSw)

        val swInHw = hardwareTags.filter { it in SOFTWARE_ONLY_TAGS }
        offenders.addAll(swInHw)

        val unknown = (hardwareTags + softwareTags).any { it !in SCHEMA_AUTHZ_TAGS }

        return Verdict(
            duplicateSchemaTag = dupes.isNotEmpty(),
            neverAttestedTagPresent = never.isNotEmpty(),
            hardwareOnlyTagInSoftwareList = hwInSw.isNotEmpty(),
            softwareOnlyTagInHardwareList = swInHw.isNotEmpty(),
            listOutOfOrder = isOutOfOrder(hardwareTags) || isOutOfOrder(softwareTags),
            unknownTagPresent = unknown,
            offendingTags = offenders.toList().sorted(),
        )
    }

    private fun duplicatesIn(tags: List<Int>): Set<Int> =
        tags.filter { it in SCHEMA_AUTHZ_TAGS }
            .groupingBy { it }
            .eachCount()
            .filterValues { it > 1 }
            .keys

    /**
     * Order over the tags outside the attestation-ID block. The ID tags are
     * exempt as members and as neighbours, because that is exactly where the
     * measured genuine records descend.
     */
    internal fun isOutOfOrder(tags: List<Int>): Boolean {
        val checked = tags.filter { it !in ATTESTATION_ID_TAGS }
        return checked.zipWithNext().any { (a, b) -> a >= b }
    }
}
