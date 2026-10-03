package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.os.Build

/**
 * How the device presents itself, used to decide whether a software-level
 * attestation chain is honest.
 *
 * Emulators, GSI images and AOSP builds legitimately attest at software level
 * with the public AOSP software attestation key, and must stay clean. What is
 * not legitimate is a software-level chain on something claiming to be
 * production hardware with a hardware-backed keystore.
 */
object DeviceIdentity {

    data class Presentation(
        val buildType: String,
        val buildTags: String,
        val fingerprint: String,
        val brand: String,
        val manufacturer: String,
        val model: String,
        val device: String,
        val product: String,
        val board: String,
        val hardware: String,
        val hardwareKeystoreDeclared: Boolean,
        /**
         * The version the device's own hardware_keystore feature declares, or 0
         * when it declares none. A vendor prebuilt, hand-pinned per release.
         */
        val keystoreFeatureVersion: Int = 0,
        val sdkInt: Int = 0,
        /** True only on a released platform, not a preview or a codenamed build. */
        val releaseBuild: Boolean = false,
    )

    val UNKNOWN = Presentation("", "", "", "", "", "", "", "", "", "", false, 0, 0, false)

    // PackageManager.FEATURE_HARDWARE_KEYSTORE (API 31) and
    // FEATURE_STRONGBOX_KEYSTORE (API 28), written as literals because minSdk is 24.
    private const val FEATURE_HARDWARE_KEYSTORE = "android.hardware.hardware_keystore"
    private const val FEATURE_STRONGBOX_KEYSTORE = "android.hardware.strongbox_keystore"

    private val VIRTUAL_HARDWARE = listOf(
        "goldfish", "ranchu", "cutf", "vsoc", "vbox", "qemu",
        "android_x86", "gce_x86", "ttvm", "nox",
    )

    private val VIRTUAL_NAME_PREFIXES = listOf(
        "sdk", "generic", "emu64", "emulator", "goldfish", "ranchu",
        "vbox", "vsoc", "cf_", "aosp_", "gsi_", "full_", "android_x86",
    )

    // Each marker carries a leading slash so it matches a whole fingerprint
    // segment and cannot collide with an OEM incremental string.
    private val VIRTUAL_FINGERPRINT_MARKERS = listOf(
        "/sdk_", "/emu64", "/generic", "/vbox", "/vsoc", "/cf_",
    )

    fun fromRuntime(context: Context): Presentation {
        return try {
            val pm = context.packageManager
            Presentation(
                buildType = Build.TYPE.orEmpty(),
                buildTags = Build.TAGS.orEmpty(),
                fingerprint = Build.FINGERPRINT.orEmpty(),
                brand = Build.BRAND.orEmpty(),
                manufacturer = Build.MANUFACTURER.orEmpty(),
                model = Build.MODEL.orEmpty(),
                device = Build.DEVICE.orEmpty(),
                product = Build.PRODUCT.orEmpty(),
                board = Build.BOARD.orEmpty(),
                hardware = Build.HARDWARE.orEmpty(),
                hardwareKeystoreDeclared =
                    pm.hasSystemFeature(FEATURE_HARDWARE_KEYSTORE) ||
                        pm.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE),
                keystoreFeatureVersion = declaredFeatureVersion(pm, FEATURE_HARDWARE_KEYSTORE),
                sdkInt = Build.VERSION.SDK_INT,
                releaseBuild = Build.VERSION.CODENAME == "REL" &&
                    Build.VERSION.PREVIEW_SDK_INT == 0,
            )
        } catch (_: Throwable) {
            UNKNOWN
        }
    }

    /**
     * The version a feature declares. getSystemAvailableFeatures carries the
     * version; hasSystemFeature(name, version) is API 24 but only answers a
     * threshold question, so the list is walked instead to read the value.
     */
    private fun declaredFeatureVersion(
        pm: android.content.pm.PackageManager,
        name: String,
    ): Int {
        return try {
            pm.systemAvailableFeatures
                .firstOrNull { it.name == name }
                ?.version
                ?: 0
        } catch (_: Throwable) {
            0
        }
    }

    /**
     * The positive mirror of the native fingerprintContradicts logic, so the
     * two cannot disagree about what a production identity looks like.
     */
    fun hasProductionBuildIdentity(p: Presentation): Boolean {
        if (p.fingerprint.isBlank() || p.brand.isBlank()) return false
        if (p.buildType != "user") return false
        if (p.buildTags != "release-keys") return false
        if (p.fingerprint.substringAfterLast(':', "") != "user/release-keys") return false
        if (p.fingerprint.count { it == '/' } < 3) return false
        return p.fingerprint.substringBefore('/', "").equals(p.brand, ignoreCase = true)
    }

    fun looksLikeVirtualDevice(p: Presentation): Boolean {
        val hardware = p.hardware.lowercase()
        if (VIRTUAL_HARDWARE.any { hardware.startsWith(it) }) return true

        val manufacturer = p.manufacturer.lowercase()
        if (manufacturer == "unknown" || manufacturer.contains("genymotion")) return true

        val names = listOf(p.product, p.device, p.model, p.board).map { it.lowercase() }
        if (names.any { name -> VIRTUAL_NAME_PREFIXES.any { name.startsWith(it) } }) return true

        val fingerprint = p.fingerprint.lowercase()
        return VIRTUAL_FINGERPRINT_MARKERS.any { fingerprint.contains(it) }
    }

    /** Every term must be provably true, so a partially readable state is false. */
    fun presentsAsPhysicalHardware(p: Presentation): Boolean =
        p.hardwareKeystoreDeclared &&
            hasProductionBuildIdentity(p) &&
            !looksLikeVirtualDevice(p)
}
