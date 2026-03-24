package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionResultTest {

    @Test
    fun cleanBitmaskReturnsAllPass() {
        val results = DetectionResult.fromBitmask(0)
        assertEquals(9, results.size)
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
        val all = 0x1FF // bits 0-8
        val results = DetectionResult.fromBitmask(all)
        assertTrue(results.all { it.detected })
    }

    @Test
    fun flagsArePowersOfTwo() {
        val flags = DetectionResult.fromBitmask(0).map { it.flag }
        assertEquals(flags.size, flags.distinct().size)
        assertTrue(flags.all { it > 0 && (it and (it - 1)) == 0 })
    }
}
