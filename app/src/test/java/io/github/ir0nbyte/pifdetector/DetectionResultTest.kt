package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionResultTest {

    @Test
    fun cleanBitmaskReturnsAllPass() {
        val results = DetectionResult.fromBitmask(0)
        assertEquals(11, results.size)
        assertTrue(results.none { it.detected })
    }

    @Test
    fun singleFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_PIF)
        val pif = results.first { it.flag == DetectionResult.DETECTION_PIF }
        assertTrue(pif.detected)
        assertTrue(results.filter { it.flag != DetectionResult.DETECTION_PIF }.none { it.detected })
    }

    @Test
    fun multipleFlags() {
        val mask = DetectionResult.DETECTION_FRIDA or
                DetectionResult.DETECTION_ZYGISK or
                DetectionResult.DETECTION_TRICKYSTORE
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(3, detected.size)
    }

    @Test
    fun allFlagsSet() {
        val all = 0x7FF // bits 0-10
        val results = DetectionResult.fromBitmask(all)
        assertTrue(results.all { it.detected })
    }

    @Test
    fun flagsArePowersOfTwo() {
        val flags = DetectionResult.fromBitmask(0).map { it.flag }
        assertEquals(flags.size, flags.distinct().size)
        assertTrue(flags.all { it > 0 && (it and (it - 1)) == 0 })
    }

    @Test
    fun pifStreamFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_PIF_STREAM)
        val stream = results.first { it.flag == DetectionResult.DETECTION_PIF_STREAM }
        assertTrue(stream.detected)
        assertEquals("PIF Companion Streaming", stream.name)
        assertTrue(
            results.filter { it.flag != DetectionResult.DETECTION_PIF_STREAM }.none { it.detected }
        )
    }

    @Test
    fun canaryFingerprintFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_CANARY_FP)
        val canary = results.first { it.flag == DetectionResult.DETECTION_CANARY_FP }
        assertTrue(canary.detected)
        assertEquals("Pixel Canary Fingerprint", canary.name)
    }

    @Test
    fun newFlagsCoexistWithLegacyFlags() {
        // PIF + companion streaming together (typical inject-s v4.5 case)
        val mask = DetectionResult.DETECTION_PIF or DetectionResult.DETECTION_PIF_STREAM
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_PIF })
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_PIF_STREAM })
    }

    @Test
    fun trickyStoreAndCanaryCoexist() {
        // PIFS detection scenario: TrickyStore keybox + canary fingerprint + motherboard spoof
        val mask = DetectionResult.DETECTION_TRICKYSTORE or
                DetectionResult.DETECTION_CANARY_FP or
                DetectionResult.DETECTION_PROP_SPOOF
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(3, detected.size)
    }
}
