package io.github.ir0nbyte.pifdetector

data class DetectionResult(
    val name: String,
    val description: String,
    val flag: Int,

    /** What this check concluded. See [CheckState]. */
    val state: CheckState,

    /**
     * Row metadata, not an outcome: this check can only ever fire when the app
     * runs privileged. Kept alongside the state so a row that cannot be seen
     * because of the sandbox can be told apart from one that cannot apply to
     * this hardware, which matters in the exported report.
     */
    val privilegedOnly: Boolean = false,

    /** Optional one line of context shown under the check description. */
    val detail: String? = null,

    /**
     * Which sub-probes set this row's bit, in the engine's words. Empty for a
     * row whose check is not wired for reasons, which simply renders as before.
     */
    val reasons: List<String> = emptyList(),
) {
    /*
     * The old boolean surface, now derived from the single state. Callers and
     * tests that predate CheckState keep working unchanged, and no caller can
     * put the row into a combination that does not mean anything.
     */
    val detected: Boolean get() = state == CheckState.DETECTED
    val warning: Boolean get() = state == CheckState.INFORMATIONAL
    val inconclusive: Boolean
        get() = state == CheckState.UNVERIFIABLE || state == CheckState.SKIPPED
    val notApplicable: Boolean
        get() = state == CheckState.NOT_OBSERVABLE && !privilegedOnly
    companion object {
        const val DETECTION_DEBUGGER = 0x001
        const val DETECTION_FRIDA = 0x002
        const val DETECTION_ZYGISK = 0x004
        const val DETECTION_PIF = 0x008
        const val DETECTION_BOOTLOADER = 0x010
        const val DETECTION_SIGNATURE = 0x020
        const val DETECTION_TRICKYSTORE = 0x040
        const val DETECTION_PROP_SPOOF = 0x080
        const val DETECTION_ROOT_HIDER = 0x100
        const val DETECTION_PIF_STREAM = 0x200
        const val DETECTION_CANARY_FP = 0x400
        const val DETECTION_TSEE = 0x800
        const val DETECTION_PIF_RUST = 0x1000
        const val DETECTION_TREAT_WHEEL = 0x2000

        const val DETECTION_ATTEST_ANOMALY = 0x4000

        const val DETECTION_ATTEST_FORGERY = 0x8000

        /**
         * Row identity only. Nothing sets this bit: see the note in
         * KeyAttestationProbe on why a revoked serial is not a device verdict.
         */
        const val DETECTION_ATTEST_REVOKED = 0x10000

        const val DETECTION_ATTEST_CROSS_SOURCE = 0x20000

        const val DETECTION_ATTEST_SOFTWARE = 0x40000

        /**
         * Only an inverted or zero-width issuer window sets this bit. An
         * expired issuer is reported on the same row without setting it: see
         * ValidityOutcome.
         */
        const val DETECTION_ATTEST_VALIDITY = 0x80000

        /**
         * Row identity only. Nothing sets this bit: see VersionBounds.Verdict
         * for why neither version arm can convict.
         */
        const val DETECTION_ATTEST_VERSION = 0x100000

        /**
         * A duplicated, never-attested or misplaced authorization tag. Tag
         * ORDER is reported without setting this: genuine retail devices emit
         * out-of-order lists.
         */
        const val DETECTION_ATTEST_SHAPE = 0x200000

        /**
         * Row identity only. Nothing sets this bit: see ModuleHash on why a
         * mismatch cannot convict.
         */
        const val DETECTION_ATTEST_MODULE_HASH = 0x400000

        /**
         * In-process code integrity: an inline hook on a libc prologue, or an
         * executable mapping from a source the platform never loads code from.
         * Both are observable without privilege, because they are facts about
         * this process's own address space.
         */
        const val DETECTION_CODE_INTEGRITY = 0x800000

        private val PRIVILEGED_ONLY = setOf(
            DETECTION_PIF,
            DETECTION_TRICKYSTORE,
            DETECTION_PIF_STREAM,
            DETECTION_TSEE,
            DETECTION_PIF_RUST,
        )

        private data class Spec(val flag: Int, val name: String, val description: String)

        private val SPECS = listOf(
            Spec(DETECTION_DEBUGGER,   "Debugger",
                 "Debugger or tracing tool attached"),
            Spec(DETECTION_FRIDA,      "Frida / Instrumentation",
                 "Frida, Xposed, or similar hooking framework"),
            Spec(DETECTION_ZYGISK,     "Zygisk / Magisk",
                 "Zygisk, Magisk, KernelSU, or APatch detected"),
            Spec(DETECTION_PIF,        "Play Integrity Fix",
                 "PIF module or fork injecting spoofed properties"),
            Spec(DETECTION_BOOTLOADER, "Bootloader Unlocked",
                 "Device bootloader is unlocked or verified boot compromised"),
            Spec(DETECTION_SIGNATURE,  "APK Signature",
                 "Application signature does not match expected value"),
            Spec(DETECTION_TRICKYSTORE,"TrickyStore / KeyboxHub",
                 "Keybox spoofing module or auto-rotating KeyboxHub detected"),
            Spec(DETECTION_PROP_SPOOF, "Property Spoofing",
                 "Build property inconsistency or motherboard spoof detected"),
            Spec(DETECTION_ROOT_HIDER, "Root Hider",
                 "Mount namespace, OverlayFS, or SELinux anomaly detected"),
            Spec(DETECTION_PIF_STREAM, "PIF Companion Streaming",
                 "inject-s v4.5 payload streamed via Zygisk companion / memfd"),
            Spec(DETECTION_CANARY_FP,  "Pixel Canary Fingerprint",
                 "autopif4 monthly Pixel Canary build fingerprint detected"),
            Spec(DETECTION_TSEE,       "TS-Enhancer-Extreme",
                 "Anti-detection module masquerading bootloader status"),
            Spec(DETECTION_PIF_RUST,   "PIF Pure Rust",
                 "PIF-Hybrid Rust edition (DobbyHook-free) detected"),
            Spec(DETECTION_TREAT_WHEEL,"Treat Wheel",
                 "Treat Wheel ReZygisk root hider mapped into the process"),
            Spec(DETECTION_ATTEST_ANOMALY, "Key Attestation",
                 "Hardware key attestation chain invalid or contradicts device state"),
            Spec(DETECTION_ATTEST_FORGERY, "Attestation Forgery (active)",
                 "Provoked attestation chain contradicts itself or is keybox-signed"),
            Spec(DETECTION_ATTEST_REVOKED, "Keybox Revocation",
                 "Attestation serial checked against Google's published revocation list"),
            Spec(DETECTION_ATTEST_CROSS_SOURCE, "Attestation Cross-Source",
                 "Attested patch levels or verified boot hash disagree with the device's own sources, or are malformed"),
            Spec(DETECTION_ATTEST_SOFTWARE, "Software Attestation",
                 "Software-level key attestation on a device presenting as production hardware"),
            Spec(DETECTION_ATTEST_VALIDITY, "Chain Validity Windows",
                 "Issuer certificate validity windows, judged without trusting the device clock"),
            Spec(DETECTION_ATTEST_VERSION, "Attestation Version Bounds",
                 "Attested schema and KeyMint versions against what this platform can emit"),
            Spec(DETECTION_ATTEST_SHAPE, "Authorization List Shape",
                 "Duplicated, never-attested or misplaced tags in the attestation record"),
            Spec(DETECTION_ATTEST_MODULE_HASH, "Module Hash Cross-Check",
                 "Attested module hash against the hash the platform reports for its own modules"),
            Spec(DETECTION_CODE_INTEGRITY, "Code Integrity",
                 "Inline hooks on libc, or executable memory from an unrecognised source"),
        )

        val ALL_FLAGS_MASK: Int = SPECS.fold(0) { acc, s -> acc or s.flag }

        fun fromBitmask(
            bitmask: Int,
            revocation: RevocationStatus? = null,
            crossSource: AttestationAnalysis.CrossSourceVerdict? = null,
            validity: ValidityStatus? = null,
            versions: VersionBounds.Verdict? = null,
            shape: RecordShape.Verdict? = null,
            moduleHash: ModuleHash.Status? = null,
            reasonCodes: List<Int> = emptyList(),
        ): List<DetectionResult> {
            val reasonsByFlag = ReasonCodes.describe(reasonCodes)
            return SPECS.map { spec ->
            val detected = bitmask and spec.flag != 0
            val privileged = PRIVILEGED_ONLY.contains(spec.flag)
            val base = DetectionResult(
                spec.name,
                spec.description,
                spec.flag,
                when {
                    detected -> CheckState.DETECTED
                    privileged -> CheckState.NOT_OBSERVABLE
                    else -> CheckState.CLEAN
                },
                privileged,
            )
            when {
                spec.flag == DETECTION_ATTEST_REVOKED && revocation != null ->
                    applyRevocation(base, revocation)

                spec.flag == DETECTION_ATTEST_CROSS_SOURCE && crossSource != null ->
                    applyCrossSource(base, crossSource)

                spec.flag == DETECTION_ATTEST_VALIDITY && validity != null ->
                    applyValidity(base, validity)

                spec.flag == DETECTION_ATTEST_VERSION && versions != null ->
                    applyVersions(base, versions)

                spec.flag == DETECTION_ATTEST_SHAPE && shape != null ->
                    applyShape(base, shape)

                spec.flag == DETECTION_ATTEST_MODULE_HASH && moduleHash != null ->
                    applyModuleHash(base, moduleHash)

                else -> base
            }.let { row ->
                val texts = reasonsByFlag[spec.flag].orEmpty()
                if (texts.isEmpty()) row else row.copy(reasons = texts)
            }
            }
        }

        private fun applyModuleHash(
            row: DetectionResult,
            status: ModuleHash.Status,
        ): DetectionResult {
            val km = status.keyMintVersion
            return when (status.outcome) {
                ModuleHash.Outcome.MATCHED -> row.copy(
                    detail = "Attested module hash matches the platform's"
                )

                ModuleHash.Outcome.MISMATCHED -> row.copy(
                    state = CheckState.INFORMATIONAL,
                    detail = "Attested module hash does not match the platform's. A staged " +
                        "mainline update applied by a userspace reboot produces the same " +
                        "difference, so this is not by itself evidence about this device."
                )

                // The tag is OPTIONAL and a known class of vendor KeyMint 4
                // TAs never implemented it, so absence is permitted.
                ModuleHash.Outcome.ABSENT -> row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "This KeyMint ${km ?: "?"} record carries no module hash. The tag " +
                        "is optional, so its absence is permitted."
                )

                ModuleHash.Outcome.MALFORMED -> row.copy(
                    state = CheckState.UNVERIFIABLE,
                    detail = "The attested module hash is not a 32-byte digest, so it was not " +
                        "compared."
                )

                ModuleHash.Outcome.UNREADABLE -> row.copy(
                    state = CheckState.UNVERIFIABLE,
                    detail = "The module hash could not be read, so nothing was compared."
                )

                ModuleHash.Outcome.NOT_APPLICABLE -> row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "Needs a KeyMint 4 record and a platform that reports its own " +
                        "module set, which this device does not provide."
                )
            }
        }

        private fun applyShape(
            row: DetectionResult,
            v: RecordShape.Verdict,
        ): DetectionResult {
            if (!v.evaluated) {
                return row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "No readable hardware-backed, Google-anchored record",
                )
            }
            val reasons = buildList {
                if (v.duplicateSchemaTag) add("a schema tag appears twice")
                if (v.neverAttestedTagPresent) add("a tag the schema never attests is present")
                if (v.hardwareOnlyTagInSoftwareList) {
                    add("a hardware-enforced-only tag is in the software-enforced list")
                }
                if (v.softwareOnlyTagInHardwareList) {
                    add("a software-enforced-only tag is in the hardware-enforced list")
                }
            }
            val tags = if (v.offendingTags.isEmpty()) {
                ""
            } else {
                " (tags ${v.offendingTags.joinToString(", ")})"
            }
            if (reasons.isNotEmpty()) {
                return row.copy(detail = reasons.joinToString("; ") + tags)
            }

            // Reported, never findings.
            val notes = buildList {
                if (v.listOutOfOrder) {
                    add("an authorization list is not in ascending tag order, which genuine " +
                        "retail devices also emit")
                }
                if (v.unknownTagPresent) add("a vendor-private or newer tag is present")
            }
            // No badge: an out-of-order list is normal on retail devices, so
            // raising one would move a clean run to Review Needed over
            // behaviour that is not even unusual.
            if (notes.isNotEmpty()) {
                return row.copy(detail = notes.joinToString("; ") + " (reported, not a finding)")
            }
            return row.copy(detail = "Both authorization lists are well formed")
        }

        private fun applyVersions(
            row: DetectionResult,
            v: VersionBounds.Verdict,
        ): DetectionResult {
            if (!v.evaluated) {
                return row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "Not evaluated: there was no readable record to bound",
                )
            }
            val claimed = "schema ${v.attestationVersion ?: "?"}, KeyMint ${v.keymasterVersion ?: "?"}"
            if (v.aheadOfPlatform) {
                val b = v.platformBound
                return row.copy(
                    state = CheckState.INFORMATIONAL,
                    detail = "Record claims $claimed, above the most this platform can emit " +
                        "(schema ${b?.attestation}, KeyMint ${b?.keyMint}). A vendor update " +
                        "that raises the secure implementation past the system image's own " +
                        "release reads the same way, so this is not by itself evidence."
                )
            }
            if (v.aheadOfDeclaredHal) {
                return row.copy(
                    state = CheckState.INFORMATIONAL,
                    detail = "Record claims KeyMint ${v.keymasterVersion} while this device's " +
                        "keystore feature declares ${v.declaredHalVersion}. That can also mean " +
                        "the vendor's feature declaration is mis-pinned, so it is not by itself " +
                        "evidence about this device."
                )
            }
            if (v.platformBound == null) {
                return row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "No bound known for this platform, so nothing was judged",
                )
            }
            return row.copy(detail = "Record claims $claimed, within this platform's bound")
        }

        private fun applyValidity(
            row: DetectionResult,
            status: ValidityStatus,
        ): DetectionResult {
            val offender = status.offenderSubject?.let { " ($it)" } ?: ""
            return when (status.outcome) {
                ValidityOutcome.IMPOSSIBLE_WINDOW -> row.copy(
                    detail = "An issuer certificate's validity window starts at or after it " +
                        "ends$offender. No certificate authority emits that."
                )

                ValidityOutcome.EXPIRED_ISSUER -> row.copy(
                    state = CheckState.INFORMATIONAL,
                    detail = "An issuer certificate lapsed " +
                        "${status.daysPastFloor ?: 0} days before the earliest time this " +
                        "device can prove has passed$offender. Google documents expired " +
                        "factory attestation keys as still trustworthy, and batch " +
                        "certificates are shared across a production run, so this is not by " +
                        "itself evidence about this device."
                )

                ValidityOutcome.RECENTLY_EXPIRED -> row.copy(
                    state = CheckState.UNVERIFIABLE,
                    detail = "An issuer certificate lapsed only recently$offender, which a " +
                        "provisioned certificate lagging a rotation also does. Not called."
                )

                // A wrong device clock is a condition of the device, not an
                // observation about the chain, and two of three genuine test
                // handsets have one. It must not turn the card amber.
                ValidityOutcome.CLOCK_BEHIND -> row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "The device clock is behind the earliest time this device can " +
                        "prove has passed, so the windows cannot be judged."
                )

                ValidityOutcome.NO_REFERENCE -> row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "No clock-independent reference was available, so nothing was judged."
                )

                ValidityOutcome.NOT_APPLICABLE -> row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "No issuer windows to judge against a reference. An inverted " +
                        "window would still have been reported."
                )

                ValidityOutcome.NOT_EVALUATED -> row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "Not evaluated: there was no chain to examine"
                )

                ValidityOutcome.VERIFIED -> row.copy(
                    detail = "Issuer windows are consistent and none has lapsed"
                )
            }
        }

        private fun applyCrossSource(
            row: DetectionResult,
            v: AttestationAnalysis.CrossSourceVerdict,
        ): DetectionResult {
            if (!v.evaluated) {
                return row.copy(
                    state = CheckState.NOT_OBSERVABLE,
                    detail = "No hardware-backed, Google-anchored chain to compare against",
                )
            }
            return row.copy(detail = crossSourceDetail(v))
        }

        /**
         * The reasons, or a readout when there is nothing to report. The
         * report-only arms deliberately do not set `warning` either: on this
         * row an observation that cannot convict belongs in the detail, and
         * raising the badge would move the whole run to Review Needed.
         */
        private fun crossSourceDetail(
            v: AttestationAnalysis.CrossSourceVerdict,
        ): String? {
            val reasons = buildList {
                if (v.osPatchAhead) {
                    add("attested OS patch level is newer than the device property")
                }
                if (v.osPatchDisagrees) {
                    add("attested OS patch level does not equal the device property " +
                        "on a locked, verified device")
                }
                if (v.malformedDayPrecisionPatchLevel) {
                    add("a day-precision patch level is neither a valid date nor a month")
                }
                if (v.bootHashMismatch) {
                    add("attested verified boot hash does not match the device's vbmeta digest")
                }
            }
            if (reasons.isNotEmpty()) return reasons.joinToString("; ")

            // Reported, never findings. The vendor arms need
            // ro.vendor.build.security_patch, whose readability is a per-vendor
            // sepolicy decision: measured empty on a Pixel 7a and a moto g04
            // and readable on a Samsung SM-G780G. An arm that is live on some
            // vendors and dead on others cannot carry a verdict.
            val notes = buildList {
                if (v.vendorPatchAhead) {
                    add("attested vendor patch level is newer than the device property")
                }
                if (v.vendorPatchCopiedFromSystemProperty) {
                    add("attested vendor patch level matches the system patch property, " +
                        "not the vendor one")
                }
                if (v.monthPrecisionDayLevel) {
                    add("a day-precision patch level carries only a month")
                }
                if (v.bootPatchLevelMissing) {
                    add("boot patch level is absent although KeyMint 3 requires it")
                }
            }
            if (notes.isNotEmpty()) return notes.joinToString("; ") + " (reported, not a finding)"
            if (v.attestedBootHashUnusable) {
                return "The attested verified boot hash carries no usable digest: it is all " +
                    "zeroes, or not 32 bytes long. That is what an implementation emits when " +
                    "it could not read the device's digest, so it is not evidence."
            }
            val boot = v.attestedBootPatchLevel
            return if (boot != null) "Attested boot patch level $boot" else null
        }

        private fun applyRevocation(
            row: DetectionResult,
            status: RevocationStatus,
        ): DetectionResult = when (status.outcome) {
            RevocationOutcome.KNOWN_REVOKED -> row.copy(
                state = CheckState.INFORMATIONAL,
                detail = "A serial in this chain is on Google's published list. " +
                    "Batch keys are shared across a production run, so this can also mean " +
                    "the manufacturer's key was published. Not by itself evidence of spoofing."
            )

            RevocationOutcome.VERIFIED -> row.copy(
                detail = verifiedDetail(status)
            )

            RevocationOutcome.UNVERIFIABLE -> row.copy(
                state = CheckState.UNVERIFIABLE,
                detail = "Could not be checked: no usable snapshot and no network. This is not a pass."
            )

            RevocationOutcome.NOT_APPLICABLE -> row.copy(
                state = CheckState.NOT_OBSERVABLE,
                detail = "No Google-anchored attestation chain to check"
            )

            RevocationOutcome.NOT_EVALUATED -> row.copy(
                state = CheckState.UNVERIFIABLE,
                detail = "Not evaluated: the chain failed an earlier trust gate"
            )
        }

        private fun verifiedDetail(status: RevocationStatus): String {
            val source = when {
                status.snapshotDate != null && status.networkConsulted ->
                    "snapshot ${status.snapshotDate} plus online refresh"
                status.snapshotDate != null -> "offline snapshot ${status.snapshotDate}"
                else -> "online list"
            }
            return "Not on the list ($source). Not known-bad; this is not proof the keybox is genuine."
        }
    }
}
