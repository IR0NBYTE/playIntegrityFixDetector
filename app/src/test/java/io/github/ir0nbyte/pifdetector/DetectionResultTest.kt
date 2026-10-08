package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionResultTest {
    @Test
    fun cleanBitmaskReturnsAllPass() {
        val results = DetectionResult.fromBitmask(0)
        assertEquals(24, results.size)
        assertTrue(results.none { it.detected })
    }

    /**
     * The revocation list revokes attestation BATCH keys, which are shared
     * across a whole production run. A stock, never-rooted handset from a batch
     * whose keybox leaked carries the same serial a spoofer would, and 26 of the
     * current entries are SOFTWARE_FLAW, meaning a defective implementation
     * rather than spoofing. So a listed serial must never mark the device.
     */
    @Test
    fun knownRevokedIsAWarningNotADetection() {
        val status = RevocationStatus(RevocationOutcome.KNOWN_REVOKED, "2026-09-30", 1759, false)
        val results = DetectionResult.fromBitmask(0, status)
        val row = results.single { it.flag == DetectionResult.DETECTION_ATTEST_REVOKED }

        assertTrue("a listed serial must not be a detection", !row.detected)
        assertTrue("it must still be surfaced", row.warning)
        assertEquals("a genuine device from a leaked batch stays clean", 0,
            results.count { it.detected })
    }

    @Test
    fun knownRevokedDetailStatesTheBatchKeyCaveat() {
        val status = RevocationStatus(RevocationOutcome.KNOWN_REVOKED, "2026-09-30", 1759, false)
        val row = DetectionResult.fromBitmask(0, status)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_REVOKED }
        val detail = row.detail!!
        assertTrue("must not assert spoofing", detail.contains("Not by itself evidence"))
        assertTrue("must explain batch sharing", detail.contains("Batch keys are shared"))
    }

    @Test
    fun onlyTheRevocationRowCanBeAWarning() {
        val status = RevocationStatus(RevocationOutcome.KNOWN_REVOKED, "2026-09-30", 1759, false)
        assertEquals(1, DetectionResult.fromBitmask(0, status).count { it.warning })
    }

    @Test
    fun unverifiableRevocationIsInconclusiveNotDetected() {
        val status = RevocationStatus(RevocationOutcome.UNVERIFIABLE, null, 0, true)
        val results = DetectionResult.fromBitmask(0, status)
        val row = results.single { it.flag == DetectionResult.DETECTION_ATTEST_REVOKED }
        assertTrue(!row.detected)
        assertTrue(row.inconclusive)
        assertEquals(1, results.count { it.inconclusive })
    }

    @Test
    fun verifiedRevocationCarriesSnapshotDate() {
        val status = RevocationStatus(RevocationOutcome.VERIFIED, "2026-09-30", 1759, false)
        val row = DetectionResult.fromBitmask(0, status)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_REVOKED }
        assertTrue(!row.detected)
        assertTrue(!row.inconclusive)
        assertTrue(row.detail!!.contains("2026-09-30"))
    }

    @Test
    fun fromBitmaskWithoutRevocationKeepsRowNeutral() {
        val row = DetectionResult.fromBitmask(0)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_REVOKED }
        assertTrue(!row.inconclusive)
        assertEquals(null, row.detail)
    }

    @Test
    fun notApplicableRevocationIsUnobservableNotUnresolved() {
        val row = DetectionResult.fromBitmask(0, RevocationStatus.NOT_APPLICABLE)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_REVOKED }
        assertTrue(!row.detected)
        assertTrue(row.notApplicable)
        assertTrue(!row.inconclusive)
    }

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

    @Test
    fun inProcessRootHiderIsNotMarkedPrivilegedOnly() {
        val treatWheel = DetectionResult.fromBitmask(0)
            .first { it.flag == DetectionResult.DETECTION_TREAT_WHEEL }
        assertTrue(!treatWheel.privilegedOnly)
    }

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
        val mask = DetectionResult.DETECTION_PIF or DetectionResult.DETECTION_PIF_STREAM
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_PIF })
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_PIF_STREAM })
    }

    @Test
    fun trickyStoreAndCanaryCoexist() {
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
        val mask = DetectionResult.DETECTION_BOOTLOADER or DetectionResult.DETECTION_ATTEST_ANOMALY
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_ATTEST_ANOMALY })
    }

    @Test
    fun tseeAndTrickyStoreCoexist() {
        val mask = DetectionResult.DETECTION_TRICKYSTORE or DetectionResult.DETECTION_TSEE
        val detected = DetectionResult.fromBitmask(mask).filter { it.detected }
        assertEquals(2, detected.size)
        assertTrue(detected.any { it.flag == DetectionResult.DETECTION_TSEE })
    }
}
