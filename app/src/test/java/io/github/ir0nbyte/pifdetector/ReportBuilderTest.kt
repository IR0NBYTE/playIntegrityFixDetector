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

    /**
     * The finding's own reason text has to land on the row its flag lights, or
     * a report says a check fired and cannot say why.
     */
    @Test
    fun theCompanionFindingNamesItselfOnTheForgeryRow() {
        val text = build(
            bitmask = DetectionResult.DETECTION_ATTEST_FORGERY,
            reasons = listOf(CompanionAlgorithmCheck.COMPANION_SOFTWARE_ROOT),
        )
        assertTrue("names the software fallback arm", text.contains("software fallback"))
        assertTrue("marks the row as a finding", text.contains("[DETECTED"))
        assertFalse(
            "the reason fell into the unattributed bucket",
            text.contains("Unrecognised reason code")
        )
    }

    /**
     * The two companion verdicts that set no bit are only ever visible in the
     * report, so a refusal or an unfamiliar root has to reach the text.
     */
    @Test
    fun theCompanionAlgorithmVerdictIsCarriedEvenWhenItSetsNoBit() {
        for (verdict in CompanionAlgorithmCheck.Verdict.entries) {
            val r = report().copy(companionAlgorithm = verdict)
            val rows = DetectionResult.fromBitmask(
                r.bitmask, r.revocation, null, null, null, null, null, r.reasons,
            )
            val text = ReportBuilder.build(rows, r, presentation, appVersion = "2.9 (11)")
            assertTrue(
                "the report dropped the $verdict verdict",
                text.contains("companion algorithm") && text.contains(verdict.name)
            )
            for (banned in listOf("BEGIN CERTIFICATE", "serial", "challenge")) {
                assertFalse(
                    "a companion verdict leaked '$banned'",
                    text.lowercase().contains(banned.lowercase())
                )
            }
        }
    }

    /**
     * The one path from a certificate into the report. Google attestation CA
     * and batch certificates name themselves by a serialNumber attribute, which
     * X500Principal.getName() renders as DER hex (2.5.4.5=#1310...), so a
     * banned-word check on "serial" cannot see it. This drives a chain whose
     * expired batch certificate carries one through the real ChainValidity path
     * and asserts nothing of its name reaches the text.
     */
    @Test
    fun anExpiredIssuerIsLocatedByPositionAndNeverNamed() {
        val year2024 = 1_704_067_200_000L
        val year2026 = 1_767_225_600_000L
        val year2030 = 1_893_456_000_000L
        val batch = ChainValidityTest.StubCert(
            "CN=Droid CA2, O=Google LLC, SERIALNUMBER=e18c4f2ca699739a, T=TEE",
            year2024 - 1, year2024, ChainValidityTest.StubKey("batch"), false,
        )
        val leaf = ChainValidityTest.StubCert(
            "CN=Android Keystore Key", 0L, year2030, ChainValidityTest.StubKey("leaf"), false,
        )
        val root = ChainValidityTest.StubCert(
            "SERIALNUMBER=f92009e853b6b045", year2024, year2030,
            ChainValidityTest.StubKey("root"), true,
        )
        val status = ChainValidity.evaluate(
            chain = listOf(leaf, batch, root),
            pinnedRoots = listOf(root),
            anchored = true,
            hardwareBacked = true,
            attestedPatchYearMonths = emptyList(),
            systemPatchYearMonth = 202601,
            nowMillis = year2026,
        )
        assertTrue(status.outcome == ValidityOutcome.EXPIRED_ISSUER)

        val r = report()
        val rows = DetectionResult.fromBitmask(
            r.bitmask, r.revocation, null, status, null, null, null, r.reasons,
        )
        val text = ReportBuilder.build(rows, r, presentation, appVersion = "2.9 (11)")
        assertTrue(
            "the offender is still located",
            text.contains("certificate 2 of 3 in the chain")
        )
        for (banned in listOf("2.5.4.5", "#13", "CN=", "SERIALNUMBER", "e18c4f2ca699739a",
            "f92009e853b6b045", "Droid CA2")) {
            assertFalse(
                "the report leaked '$banned'",
                text.uppercase().contains(banned.uppercase())
            )
        }
    }

    /** An offender that cannot be located renders no position rather than a guess. */
    @Test
    fun anUnlocatedOffenderRendersNoPosition() {
        val status = ValidityStatus(ValidityOutcome.RECENTLY_EXPIRED)
        val row = DetectionResult.fromBitmask(0, null, null, status)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_VALIDITY }
        assertTrue(row.detail!!.contains("lapsed only recently"))
        assertFalse(row.detail!!.contains("in the chain"))
        assertFalse(row.detail!!.contains("("))
    }
}
