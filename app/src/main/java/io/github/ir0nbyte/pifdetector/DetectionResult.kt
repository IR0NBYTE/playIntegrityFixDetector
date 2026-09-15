package io.github.ir0nbyte.pifdetector

data class DetectionResult(
    val name: String,
    val description: String,
    val flag: Int,
    val detected: Boolean,

    val privilegedOnly: Boolean = false
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
        )

        val ALL_FLAGS_MASK: Int = SPECS.fold(0) { acc, s -> acc or s.flag }

        fun fromBitmask(bitmask: Int): List<DetectionResult> = SPECS.map {
            DetectionResult(
                it.name,
                it.description,
                it.flag,
                bitmask and it.flag != 0,
                PRIVILEGED_ONLY.contains(it.flag)
            )
        }
    }
}
