package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The report is what a user pastes into an issue, so the things worth asserting
 * are that it carries the evidence a screenshot cannot and that it carries
 * nothing it should not.
 */
class ReportBuilderTest {

    private val presentation = DeviceIdentity.Presentation(
        buildType = "user",
        buildTags = "release-keys",
        fingerprint = "google/lynx/lynx:15/AP4A/1234:user/release-keys",
        brand = "google",
        manufacturer = "Google",
        model = "Pixel 7a",
        device = "lynx",
        product = "lynx",
        board = "lynx",
        hardware = "",
        hardwareKeystoreDeclared = true,
        keystoreFeatureVersion = 300,
        sdkInt = 35,
        releaseBuild = true,
    )

    private fun report(reasons: List<Int> = emptyList(), bitmask: Int = 0) = DetectionReport(
        bitmask = bitmask,
        revocation = RevocationStatus(
            outcome = RevocationOutcome.VERIFIED,
            snapshotDate = "2026-09-30",
            snapshotEntryCount = 1742,
            networkConsulted = false,
        ),
        reasons = reasons,
    )

    private fun build(bitmask: Int = 0, reasons: List<Int> = emptyList()): String {
        val r = report(reasons, bitmask)
        val rows = DetectionResult.fromBitmask(
            r.bitmask, r.revocation, null, null, null, null, null, r.reasons,
        )
        return ReportBuilder.build(rows, r, presentation, appVersion = "2.9 (11)")
    }

    /** The whole point of D3: the report names the arm that fired. */
    @Test
    fun theReportNamesTheExactArmThatFired() {
        val text = build(
            bitmask = DetectionResult.DETECTION_BOOTLOADER,
            reasons = listOf(504, 506),
        )
        assertTrue("names the flash.locked arm", text.contains("flash.locked"))
        assertTrue("names the ro.debuggable arm", text.contains("ro.debuggable"))
        assertTrue("marks the row as a finding", text.contains("[DETECTED"))
    }

    @Test
    fun everyCheckAppearsWithAState() {
        val text = build()
        val rows = DetectionResult.fromBitmask(0)
        for (row in rows) {
            assertTrue("missing row ${row.name}", text.contains(row.name))
        }
    }

    @Test
    fun theSnapshotDateAndSizeAreRecorded() {
        val text = build()
        assertTrue(text.contains("2026-09-30"))
        assertTrue(text.contains("1742"))
    }

    @Test
    fun buildIdentityIsRecorded() {
        val text = build()
        assertTrue(text.contains("google/lynx/lynx:15/AP4A/1234:user/release-keys"))
        assertTrue(text.contains("Pixel 7a"))
        assertTrue(text.contains("2.9 (11)"))
    }

    @Test
    fun theSummaryCountsEveryRowExactlyOnce() {
        val text = build()
        val rows = DetectionResult.fromBitmask(0)
        val counts = Regex("""(findings|needs review|passed|not observable)\s+(\d+)""")
            .findAll(text).map { it.groupValues[2].toInt() }.sum()
        assertTrue("summary should account for all ${rows.size} rows", counts == rows.size)
    }

    /**
     * An empty field would otherwise print as nothing at all, which reads as a
     * missing line rather than as a device that does not expose the value.
     */
    @Test
    fun absentDeviceValuesSaySoRatherThanPrintingBlank() {
        val text = build()
        assertTrue("hardware is empty on this fixture", text.contains("unknown"))
    }

    /** Nothing identifying the key material belongs in a pasted report. */
    @Test
    fun theReportCarriesNoKeyMaterial() {
        val text = build(
            bitmask = DetectionResult.DETECTION_BOOTLOADER,
            reasons = listOf(504),
        ).lowercase()
        for (banned in listOf("begin certificate", "serial", "challenge", "private")) {
            assertFalse("report must not contain '$banned'", text.contains(banned))
        }
    }

    @Test
    fun aRowWithoutReasonsStillRenders() {
        val text = build(bitmask = DetectionResult.DETECTION_TREAT_WHEEL)
        assertTrue(text.contains("Treat Wheel"))
    }
}
