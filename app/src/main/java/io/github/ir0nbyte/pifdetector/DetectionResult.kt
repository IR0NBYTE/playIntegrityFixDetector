package io.github.ir0nbyte.pifdetector

data class DetectionResult(
    val name: String,
    val description: String,
    val flag: Int,
    val detected: Boolean
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

        fun fromBitmask(bitmask: Int): List<DetectionResult> = listOf(
            DetectionResult(
                "Debugger",
                "Debugger or tracing tool attached",
                DETECTION_DEBUGGER,
                bitmask and DETECTION_DEBUGGER != 0
            ),
            DetectionResult(
                "Frida / Instrumentation",
                "Frida, Xposed, or similar hooking framework",
                DETECTION_FRIDA,
                bitmask and DETECTION_FRIDA != 0
            ),
            DetectionResult(
                "Zygisk / Magisk",
                "Zygisk, Magisk, KernelSU, or APatch detected",
                DETECTION_ZYGISK,
                bitmask and DETECTION_ZYGISK != 0
            ),
            DetectionResult(
                "Play Integrity Fix",
                "PIF module or fork injecting spoofed properties",
                DETECTION_PIF,
                bitmask and DETECTION_PIF != 0
            ),
            DetectionResult(
                "Bootloader Unlocked",
                "Device bootloader is unlocked or verified boot compromised",
                DETECTION_BOOTLOADER,
                bitmask and DETECTION_BOOTLOADER != 0
            ),
            DetectionResult(
                "APK Signature",
                "Application signature does not match expected value",
                DETECTION_SIGNATURE,
                bitmask and DETECTION_SIGNATURE != 0
            ),
            DetectionResult(
                "TrickyStore",
                "TrickyStore keybox spoofing module detected",
                DETECTION_TRICKYSTORE,
                bitmask and DETECTION_TRICKYSTORE != 0
            ),
            DetectionResult(
                "Property Spoofing",
                "Build properties inconsistent or hook detected",
                DETECTION_PROP_SPOOF,
                bitmask and DETECTION_PROP_SPOOF != 0
            ),
            DetectionResult(
                "Root Hider",
                "Mount namespace, OverlayFS, or SELinux anomaly detected",
                DETECTION_ROOT_HIDER,
                bitmask and DETECTION_ROOT_HIDER != 0
            )
        )
    }
}
