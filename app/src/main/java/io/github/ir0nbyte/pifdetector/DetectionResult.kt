package io.github.ir0nbyte.pifdetector

data class DetectionResult(
    val name: String,
    val description: String,
    val flag: Int,
    val detected: Boolean,

    val privilegedOnly: Boolean = false,

    /**
     * Observable in principle, but this run could not reach a verdict. Rendered
     * as its own state and counted as neither a pass nor a detection.
     */
    val inconclusive: Boolean = false,

    /**
     * A real observation that is worth showing but is not by itself evidence
     * about this device. Counted as neither a pass nor a detection.
     */
    val warning: Boolean = false,

    /** Optional one line of context shown under the check description. */
    val detail: String? = null,
) {
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
                 "Attested patch level or verified boot hash disagrees with the device's own sources"),
            Spec(DETECTION_ATTEST_SOFTWARE, "Software Attestation",
                 "Software-level key attestation on a device presenting as production hardware"),
        )

        val ALL_FLAGS_MASK: Int = SPECS.fold(0) { acc, s -> acc or s.flag }

        fun fromBitmask(
            bitmask: Int,
            revocation: RevocationStatus? = null,
        ): List<DetectionResult> = SPECS.map { spec ->
            val base = DetectionResult(
                spec.name,
                spec.description,
                spec.flag,
                bitmask and spec.flag != 0,
                PRIVILEGED_ONLY.contains(spec.flag)
            )
            if (spec.flag == DETECTION_ATTEST_REVOKED && revocation != null) {
                applyRevocation(base, revocation)
            } else {
                base
            }
        }

        private fun applyRevocation(
            row: DetectionResult,
            status: RevocationStatus,
        ): DetectionResult = when (status.outcome) {
            RevocationOutcome.KNOWN_REVOKED -> row.copy(
                warning = true,
                detail = "A serial in this chain is on Google's published list. " +
                    "Batch keys are shared across a production run, so this can also mean " +
                    "the manufacturer's key was published. Not by itself evidence of spoofing."
            )

            RevocationOutcome.VERIFIED -> row.copy(
                detail = verifiedDetail(status)
            )

            RevocationOutcome.UNVERIFIABLE -> row.copy(
                inconclusive = true,
                detail = "Could not be checked: no usable snapshot and no network. This is not a pass."
            )

            RevocationOutcome.NOT_APPLICABLE -> row.copy(
                inconclusive = true,
                detail = "No Google-anchored attestation chain to check"
            )

            RevocationOutcome.NOT_EVALUATED -> row.copy(
                inconclusive = true,
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
