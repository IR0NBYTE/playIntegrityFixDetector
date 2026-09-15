package io.github.ir0nbyte.pifdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeEngineInvariantsTest {
    @Test
    fun everyObfuscatedPropertyNameDecodesCleanly() {
        val runner = DetectionRunner()
        assertEquals(
            "a property literal does not decode to a valid property name",
            0,
            runner.malformedPropertyLiterals()
        )
    }

    @Test
    fun nativeAndKotlinFlagMasksAgree() {
        val runner = DetectionRunner()
        assertTrue(
            "native mask does not match DetectionResult.ALL_FLAGS_MASK",
            runner.verifyFlagsInSync(DetectionResult.ALL_FLAGS_MASK)
        )
    }
}
