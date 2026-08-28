package io.github.ir0nbyte.pifdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/*
 * Invariants of the native engine that only hold on a real Android runtime.
 *
 * Both of these guard against the same failure mode, which this codebase has
 * hit twice: a check that stops working without changing what a clean device
 * reports. The removed obfuscation VM returned false for three checks for
 * months, and two mis-encoded property literals silently disabled both
 * bootloader-unlock fallbacks. Neither was visible in any output, so neither
 * was caught by looking.
 */
@RunWith(AndroidJUnit4::class)
class NativeEngineInvariantsTest {

    /*
     * Every obfuscated property name must decode to a well-formed Android
     * property name.
     *
     * ro.boot.veritymode decoded to `ro.boot.verigb"old"` and
     * ro.boot.flash.locked to a run of control bytes. __system_property_get
     * writes nothing for a name that does not exist and reports no error, so
     * `veritymode == "disabled"` and `flash_locked == "0"` were constant-false
     * on every device, compromised or not.
     */
    @Test
    fun everyObfuscatedPropertyNameDecodesCleanly() {
        val runner = DetectionRunner()
        assertEquals(
            "a property literal does not decode to a valid property name",
            0,
            runner.malformedPropertyLiterals()
        )
    }

    /*
     * The native flag registry and the Kotlin one must agree. Adding a flag on
     * only one side would otherwise misalign every bit above it.
     */
    @Test
    fun nativeAndKotlinFlagMasksAgree() {
        val runner = DetectionRunner()
        assertTrue(
            "native mask does not match DetectionResult.ALL_FLAGS_MASK",
            runner.verifyFlagsInSync(DetectionResult.ALL_FLAGS_MASK)
        )
    }
}
