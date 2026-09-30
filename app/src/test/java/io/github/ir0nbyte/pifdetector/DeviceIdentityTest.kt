package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Identity strings are the real ones measured from the Pixel 7a test device and
 * from stock Android Studio AVDs. The emulator cases are the false-positive
 * surface: a software attestation chain is legitimate there and must stay clean.
 */
class DeviceIdentityTest {

    private fun pixel7a(
        hardwareKeystore: Boolean = true,
    ) = DeviceIdentity.Presentation(
        buildType = "user",
        buildTags = "release-keys",
        fingerprint = "google/lynx/lynx:15/AP4A.241205.013/12621605:user/release-keys",
        brand = "google",
        manufacturer = "Google",
        model = "Pixel 7a",
        device = "lynx",
        product = "lynx",
        board = "lynx",
        hardware = "lynx",
        hardwareKeystoreDeclared = hardwareKeystore,
    )

    /**
     * Measured verbatim from a running stock AVD. Note hardwareKeystoreDeclared
     * is genuinely true there, and the build identity is fully production
     * looking, so only the virtual-device markers keep it clean.
     */
    private fun stockAvd() = DeviceIdentity.Presentation(
        buildType = "user",
        buildTags = "release-keys",
        fingerprint =
            "google/sdk_gphone64_arm64/emu64a:14/UE1A.230829.036.A4/12096271:user/release-keys",
        brand = "google",
        manufacturer = "Google",
        model = "sdk_gphone64_arm64",
        device = "emu64a",
        product = "sdk_gphone64_arm64",
        board = "goldfish_arm64",
        hardware = "ranchu",
        hardwareKeystoreDeclared = true,
    )

    /** A second measured AVD, Android 16, to pin the newer image shape too. */
    private fun stockAvdApi36() = stockAvd().copy(
        fingerprint =
            "google/sdk_gphone64_arm64/emu64a:16/BP41.250822.007/14042983:user/release-keys",
    )

    private fun cuttlefish() = DeviceIdentity.Presentation(
        buildType = "userdebug",
        buildTags = "dev-keys",
        fingerprint = "Android/cf_x86_64_phone/vsoc_x86_64:15/AOSP/1:userdebug/dev-keys",
        brand = "Android",
        manufacturer = "Google",
        model = "Cuttlefish x86_64 phone",
        device = "vsoc_x86_64",
        product = "cf_x86_64_phone",
        board = "cutf",
        hardware = "cutf_cvm",
        hardwareKeystoreDeclared = false,
    )

    @Test
    fun genuinePixelPresentsAsPhysicalHardware() {
        assertTrue(DeviceIdentity.presentsAsPhysicalHardware(pixel7a()))
    }

    @Test
    fun genuinePixelHasProductionIdentity() {
        assertTrue(DeviceIdentity.hasProductionBuildIdentity(pixel7a()))
        assertFalse(DeviceIdentity.looksLikeVirtualDevice(pixel7a()))
    }

    /** The primary false-positive guard: a stock AVD must never be flagged. */
    @Test
    fun stockAvdIsRecognisedAsVirtual() {
        assertTrue(DeviceIdentity.looksLikeVirtualDevice(stockAvd()))
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(stockAvd()))
    }

    @Test
    fun stockAvdHasProductionLookingBuildButIsStillExcluded() {
        // This is exactly the shape that made the old blanket exemption a
        // false-negative surface: production build identity, virtual hardware.
        assertTrue(DeviceIdentity.hasProductionBuildIdentity(stockAvd()))
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(stockAvd()))
    }

    @Test
    fun stockAvdApi36IsAlsoExcluded() {
        assertTrue(DeviceIdentity.looksLikeVirtualDevice(stockAvdApi36()))
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(stockAvdApi36()))
    }

    @Test
    fun cuttlefishIsExcluded() {
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(cuttlefish()))
    }

    @Test
    fun deviceWithoutHardwareKeystoreIsExcluded() {
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(pixel7a(hardwareKeystore = false)))
    }

    @Test
    fun userdebugBuildIsNotProductionIdentity() {
        val p = pixel7a().copy(
            buildType = "userdebug",
            fingerprint = "google/lynx/lynx:15/AP4A.241205.013/12621605:userdebug/dev-keys",
        )
        assertFalse(DeviceIdentity.hasProductionBuildIdentity(p))
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(p))
    }

    @Test
    fun brandNotMatchingFingerprintIsNotProductionIdentity() {
        assertFalse(DeviceIdentity.hasProductionBuildIdentity(pixel7a().copy(brand = "samsung")))
    }

    @Test
    fun unknownStateNeverPresentsAsHardware() {
        assertFalse(DeviceIdentity.presentsAsPhysicalHardware(DeviceIdentity.UNKNOWN))
        assertFalse(DeviceIdentity.hasProductionBuildIdentity(DeviceIdentity.UNKNOWN))
    }

    @Test
    fun genymotionIsExcluded() {
        assertTrue(
            DeviceIdentity.looksLikeVirtualDevice(
                pixel7a().copy(manufacturer = "Genymotion")
            )
        )
    }

    /** An OEM incremental string must not trip a fingerprint marker. */
    @Test
    fun oemIncrementalContainingGenericIsNotVirtual() {
        val p = pixel7a().copy(
            brand = "samsung",
            fingerprint = "samsung/a54xnaxx/a54x:14/UP1A.231005.007/S906generic123:user/release-keys",
            manufacturer = "samsung", model = "SM-A546B", device = "a54x",
            product = "a54xnaxx", board = "s5e8835", hardware = "s5e8835",
        )
        assertFalse(DeviceIdentity.looksLikeVirtualDevice(p))
    }
}
