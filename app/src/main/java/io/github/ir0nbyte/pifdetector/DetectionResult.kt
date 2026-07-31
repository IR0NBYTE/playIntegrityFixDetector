package io.github.ir0nbyte.pifdetector

data class DetectionResult(
    val name: String,
    val description: String,
    val flag: Int,
    val detected: Boolean,
    /*
     * True for checks that CANNOT fire from an unprivileged untrusted_app, so a
     * "pass" from them means "not observable", not "clean". See the
     * PRIVILEGED_ONLY notes below. Surfaced in the UI so the result list never
     * implies coverage the sandbox does not permit.
     */
    val privilegedOnly: Boolean = false
) {
    companion object {
        /*
         * Flag bit values are owned by the native side (see DETECTION_*
         * constants in native-lib.cpp). These Kotlin mirrors exist for
         * ergonomics; DetectionRunner.verifyFlagsInSync() asserts at
         * runtime that the OR of all KNOWN_FLAGS matches the native
         * nativeAllFlagsMask(). If you add a flag, add it in BOTH places.
         */
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

        /*
         * Produced Kotlin-side by KeyAttestationProbe (the AndroidKeyStore
         * attestation API lives in Java land), not by the native engine. It is
         * still registered in the native nativeAllFlagsMask() so the SSOT
         * assertion holds -- the native mask is the registry of all defined
         * flag bits, regardless of which layer sets them.
         */
        const val DETECTION_ATTEST_ANOMALY = 0x4000

        /*
         * Flags whose underlying checks cannot fire from an unprivileged
         * untrusted_app, verified against both the module sources and AOSP
         * sepolicy:
         *
         *  - PIF / PIF_STREAM / PIF_RUST: every Zygisk PIF fork gates on
         *    app_data_dir ending in /com.google.android.gms or
         *    /com.android.vending and calls DLCLOSE_MODULE_LIBRARY everywhere
         *    else, so the module is never resident in this process to be found
         *    in /proc/self/maps.
         *  - TRICKYSTORE: the keybox spoofers ptrace-inject into keystore2 and
         *    hook ioctl in that process, not ours. Their effect reaches us only
         *    through the attestation chain, which ATTEST_ANOMALY and
         *    ATTEST_FORGERY cover.
         *  - TSEE: the current FS-Enhancer-Extreme has no Zygisk component at
         *    all; it is root-side scripts plus global resetprop.
         *
         * All five also probe /data/adb, which SELinux denies. They are kept
         * because they DO fire when the detector runs privileged (root/adb),
         * but they must never be presented as unprivileged coverage.
         *
         * TREAT_WHEEL is deliberately NOT in this set: it is a ReZygisk root
         * hider that loads into every app process including ours, so its
         * in-process maps scan genuinely fires.
         */
        private val PRIVILEGED_ONLY = setOf(
            DETECTION_PIF,
            DETECTION_TRICKYSTORE,
            DETECTION_PIF_STREAM,
            DETECTION_TSEE,
            DETECTION_PIF_RUST,
        )

        private data class Spec(val flag: Int, val name: String, val description: String)

        // Ordered by flag value so display order matches numeric sequence.
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
        )

        // Derived from SPECS so adding a Spec automatically updates the mask.
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
