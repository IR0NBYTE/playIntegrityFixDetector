package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionResultTest {

    @Test
    fun cleanBitmaskReturnsAllPass() {
        val results = DetectionResult.fromBitmask(0)
        assertEquals(16, results.size)
        assertTrue(results.none { it.detected })
    }

    /*
     * The five checks whose evidence lives outside this process (PIF forks
     * dlclose everywhere but GMS; keybox spoofers hook keystore2; FSEE has no
     * in-process component) plus /data/adb, which SELinux denies. They must be
     * marked so the UI never renders them as a pass.
     */
    @Test
    fun unreachableChecksAreMarkedPrivilegedOnly() {
        val privileged = DetectionResult.fromBitmask(0)
            .filter { it.privilegedOnly }
            .map { it.flag }
            .toSet()
        assertEquals(
            setOf(
                DetectionResult.DETECTION_PIF,
                DetectionResult.DETECTION_TRICKYSTORE,
                DetectionResult.DETECTION_PIF_STREAM,
                DetectionResult.DETECTION_TSEE,
                DetectionResult.DETECTION_PIF_RUST,
            ),
            privileged
        )
    }

    /*
     * Treat Wheel is a ReZygisk root hider that loads into every app process,
     * so unlike the PIF forks its in-process maps scan genuinely fires. Pinned
     * here because it sits next to the unreachable set and is easy to lump in.
     */
    @Test
    fun inProcessRootHiderIsNotMarkedPrivilegedOnly() {
        val treatWheel = DetectionResult.fromBitmask(0)
            .first { it.flag == DetectionResult.DETECTION_TREAT_WHEEL }
        assertTrue(!treatWheel.privilegedOnly)
    }

    /* A privileged-only check still reports normally when it does fire. */
    @Test
    fun privilegedOnlyCheckStillReportsWhenDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_TSEE)
        val tsee = results.first { it.flag == DetectionResult.DETECTION_TSEE }
        assertTrue(tsee.detected)
        assertTrue(tsee.privilegedOnly)
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
        val results = DetectionResult.fromBitmask(DetectionResult.ALL_FLAGS_MASK)
        assertTrue(results.all { it.detected })
    }

    @Test
    fun allFlagsMaskMatchesIndividualOr() {
        val computed = DetectionResult.fromBitmask(0)
            .map { it.flag }
            .reduce { a, b -> a or b }
        assertEquals(DetectionResult.ALL_FLAGS_MASK, computed)
    }

    @Test
    fun resultsSortedByFlagValue() {
        val flags = DetectionResult.fromBitmask(0).map { it.flag }
        assertEquals(flags.sorted(), flags)
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

    @Test
    fun tseeFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_TSEE)
        val tsee = results.first { it.flag == DetectionResult.DETECTION_TSEE }
        assertTrue(tsee.detected)
        assertEquals("TS-Enhancer-Extreme", tsee.name)
        assertTrue(
            results.filter { it.flag != DetectionResult.DETECTION_TSEE }.none { it.detected }
        )
    }

    @Test
    fun rustPifFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_PIF_RUST)
        val rust = results.first { it.flag == DetectionResult.DETECTION_PIF_RUST }
        assertTrue(rust.detected)
        assertEquals("PIF Pure Rust", rust.name)
    }

    @Test
    fun treatWheelFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_TREAT_WHEEL)
        val tw = results.first { it.flag == DetectionResult.DETECTION_TREAT_WHEEL }
        assertTrue(tw.detected)
        assertEquals("Treat Wheel", tw.name)
        assertTrue(
            results.filter { it.flag != DetectionResult.DETECTION_TREAT_WHEEL }.none { it.detected }
        )
    }

    @Test
    fun treatWheelAndRootHiderCoexist() {
        // Treat Wheel is a ReZygisk root hider that typically rides alongside the
        // generic root-hider anomaly signals (mount NS / OverlayFS / SELinux).
        val mask = DetectionResult.DETECTION_ROOT_HIDER or DetectionResult.DETECTION_TREAT_WHEEL
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_TREAT_WHEEL })
    }

    @Test
    fun attestAnomalyFlagDetected() {
        val results = DetectionResult.fromBitmask(DetectionResult.DETECTION_ATTEST_ANOMALY)
        val attest = results.first { it.flag == DetectionResult.DETECTION_ATTEST_ANOMALY }
        assertTrue(attest.detected)
        assertEquals("Key Attestation", attest.name)
        assertTrue(
            results.filter { it.flag != DetectionResult.DETECTION_ATTEST_ANOMALY }.none { it.detected }
        )
    }

    @Test
    fun attestAnomalyAndBootloaderCoexist() {
        // The typical STRONG-spoof contradiction: attestation claims a locked
        // device while the bootloader signal proves otherwise.
        val mask = DetectionResult.DETECTION_BOOTLOADER or DetectionResult.DETECTION_ATTEST_ANOMALY
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_ATTEST_ANOMALY })
    }

    @Test
    fun tseeAndTrickyStoreCoexist() {
        // TS-Enhancer-Extreme requires TrickyStore as a base (typical combo)
        val mask = DetectionResult.DETECTION_TRICKYSTORE or DetectionResult.DETECTION_TSEE
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_TSEE })
    }
}
