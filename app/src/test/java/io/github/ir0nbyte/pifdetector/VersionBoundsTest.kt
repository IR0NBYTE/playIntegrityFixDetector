package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A reimplementation has to pick a version number, and TEESimulator-RS changed
 * this field twice after detectors read it. But only a version the running
 * platform cannot emit is a finding: a genuine device under the requirements
 * freeze stays on the version it launched with, so lower is ordinary.
 */
class VersionBoundsTest {

    private val pixel7a = DeviceIdentity.Presentation(
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
        hardwareKeystoreDeclared = true,
        keystoreFeatureVersion = 300,
        sdkInt = 35,
        releaseBuild = true,
    )

    @Test
    fun theGroundTruthTargetsSitExactlyAtTheirBound() {
        // Pixel 7a: SDK 35, record 300/300, feature 300.
        assertFalse(evaluate(300, 300, sdkInt = 35, declared = 300).isFinding)
        // API 36 emulator: hardware_keystore=400, record 400/400.
        assertFalse(evaluate(400, 400, sdkInt = 36, declared = 400).isFinding)
        // API 34 emulator sits at the 300 bound.
        assertFalse(evaluate(300, 300, sdkInt = 34, declared = 300).isFinding)
    }

    /**
     * Reported, never called. The named adversary moved this field in the LOW
     * direction, so a high-side comparison would not have caught it, and a
     * vendor TA update past the system image's own release is a genuine device
     * reading as ahead of its bound.
     */
    @Test
    fun aVersionAboveThePlatformBoundIsReportedNotCalled() {
        val v = evaluate(400, 400, sdkInt = 35, declared = 300)
        assertTrue(v.aheadOfPlatform)
        assertFalse(v.isFinding)

        val row = DetectionResult.fromBitmask(0, null, null, null, v)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_VERSION }
        assertFalse(row.detected)
    }

    /** Nothing in this check can set the bit, whatever the inputs. */
    @Test
    fun noInputEverSetsTheBit() {
        for (att in listOf(null, 1, 300, 400, 900)) {
            for (km in listOf(null, 1, 300, 400, 900)) {
                for (sdk in listOf(24, 33, 35, 36, 38)) {
                    assertFalse(evaluate(att, km, sdkInt = sdk, declared = 300).isFinding)
                }
            }
        }
    }

    /** The freeze means a genuine Android 16 phone can report KeyMint 1. */
    @Test
    fun aVersionBelowTheBoundIsOrdinary() {
        val v = evaluate(100, 100, sdkInt = 36, declared = 400)
        assertFalse(v.aheadOfPlatform)
        assertFalse(v.isFinding)
    }

    /**
     * A GSI or system-only image puts an older system partition over a newer
     * vendor partition, so the record legitimately exceeds the system image's
     * own SDK bound.
     */
    @Test
    fun theGsiClassIsExcludedByThePhysicalHardwareGate() {
        val v = VersionBounds.evaluate(
            attestationVersion = 400,
            keymasterVersion = 400,
            securityLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            declaredKeystoreFeatureVersion = 300,
            sdkInt = 35,
            releaseBuild = true,
            presentsAsPhysicalHardware = false,
        )
        assertFalse(v.aheadOfPlatform)
        assertFalse(v.isFinding)
    }

    /**
     * A vendor that upgraded its TA to KeyMint 4 but left the feature file
     * pinned at 300 is genuine, so this is reported and never called.
     */
    @Test
    fun aheadOfTheDeclaredHalIsAWarningNotAFinding() {
        val v = evaluate(400, 400, sdkInt = 36, declared = 300)
        assertTrue(v.aheadOfDeclaredHal)
        assertFalse(v.isFinding)

        val row = DetectionResult.fromBitmask(0, null, null, null, v)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_VERSION }
        assertFalse(row.detected)
        assertTrue(row.warning)
        assertTrue(row.detail!!.contains("mis-pinned"))
    }

    /**
     * CTS binds the feature version to keymasterVersion only. A genuine device
     * can emit a v400 record, to carry a module hash, from a KeyMint 3 TA.
     */
    @Test
    fun aNewerSchemaOnAnOlderTaIsNotComparedAgainstTheHal() {
        val v = evaluate(400, 300, sdkInt = 36, declared = 300)
        assertFalse(v.aheadOfDeclaredHal)
        assertFalse(v.isFinding)
    }

    /** StrongBox has no versioned feature file to compare against. */
    @Test
    fun strongBoxRecordsSkipTheHalArm() {
        val v = VersionBounds.evaluate(
            attestationVersion = 400,
            keymasterVersion = 400,
            securityLevel = AttestationAnalysis.SECURITY_LEVEL_STRONGBOX,
            declaredKeystoreFeatureVersion = 300,
            sdkInt = 36,
            releaseBuild = true,
            presentsAsPhysicalHardware = true,
        )
        assertFalse(v.aheadOfDeclaredHal)
        assertEquals(0, v.declaredHalVersion)
    }

    @Test
    fun softwareRecordsSkipTheHalArm() {
        val v = VersionBounds.evaluate(
            attestationVersion = 3,
            keymasterVersion = 4,
            securityLevel = AttestationAnalysis.SECURITY_LEVEL_SOFTWARE,
            declaredKeystoreFeatureVersion = 300,
            sdkInt = 34,
            releaseBuild = true,
            presentsAsPhysicalHardware = false,
        )
        assertFalse(v.aheadOfDeclaredHal)
        assertFalse(v.isFinding)
    }

    @Test
    fun aDeviceDeclaringNoKeystoreFeatureSkipsTheHalArm() {
        assertFalse(evaluate(400, 400, sdkInt = 36, declared = 0).aheadOfDeclaredHal)
        // A non-centennial declaration is not a KeyMint version at all.
        assertFalse(evaluate(400, 400, sdkInt = 36, declared = 41).aheadOfDeclaredHal)
    }

    @Test
    fun theBoundTableCoversEveryShippedRelease() {
        assertEquals(4, VersionBounds.platformVersionBound(30, true)!!.attestation)
        assertEquals(41, VersionBounds.platformVersionBound(30, true)!!.keyMint)
        assertEquals(100, VersionBounds.platformVersionBound(31, true)!!.attestation)
        assertEquals(100, VersionBounds.platformVersionBound(32, true)!!.attestation)
        assertEquals(200, VersionBounds.platformVersionBound(33, true)!!.attestation)
        assertEquals(300, VersionBounds.platformVersionBound(34, true)!!.attestation)
        assertEquals(300, VersionBounds.platformVersionBound(35, true)!!.attestation)
        assertEquals(400, VersionBounds.platformVersionBound(36, true)!!.attestation)
        assertEquals(500, VersionBounds.platformVersionBound(37, true)!!.attestation)
    }

    /**
     * An SDK past the table must say nothing. Extrapolating would turn every
     * handset on the next Android release into a finding.
     */
    @Test
    fun anUnknownPlatformIsNoEvidence() {
        assertNull(VersionBounds.platformVersionBound(38, true))
        assertNull(VersionBounds.platformVersionBound(0, true))
        assertNull(VersionBounds.platformVersionBound(-1, true))
        val v = evaluate(900, 900, sdkInt = 38, declared = 400)
        assertFalse(v.isFinding)

        // With no declared feature version the HAL arm is silent too, so the
        // row has nothing to say and must read as not observable.
        val silent = evaluate(900, 900, sdkInt = 38, declared = 0)
        assertFalse(silent.isFinding)
        assertFalse(silent.aheadOfDeclaredHal)
        val row = DetectionResult.fromBitmask(0, null, null, null, silent)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_VERSION }
        assertFalse(row.detected)
        assertTrue(row.notApplicable)
        assertFalse(row.inconclusive)
    }

    /** A preview or codenamed build has no frozen AIDL to bound it. */
    @Test
    fun aPreviewBuildIsNoEvidence() {
        assertNull(VersionBounds.platformVersionBound(36, false))
        assertFalse(evaluate(900, 900, sdkInt = 36, declared = 400, release = false).isFinding)
    }

    @Test
    fun anUnreadableRecordIsNoEvidence() {
        val v = VersionBounds.evaluate(
            attestationVersion = null,
            keymasterVersion = null,
            securityLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            declaredKeystoreFeatureVersion = 300,
            sdkInt = 35,
            releaseBuild = true,
            presentsAsPhysicalHardware = true,
        )
        assertEquals(VersionBounds.Verdict.NONE, v)
        assertFalse(v.isFinding)
    }

    @Test
    fun notEvaluatedIsNotAPass() {
        val row = DetectionResult.fromBitmask(
            0, null, null, null, VersionBounds.Verdict.NOT_EVALUATED
        ).single { it.flag == DetectionResult.DETECTION_ATTEST_VERSION }
        assertFalse("it must not read as a pass", row.detected)
        assertTrue("there was no record to bound, so it is unobservable", row.notApplicable)
        assertFalse("and must not turn the card amber", row.inconclusive)
    }

    @Test
    fun thePixelPresentationReadsAsPhysicalHardware() {
        assertTrue(DeviceIdentity.presentsAsPhysicalHardware(pixel7a))
        assertEquals(300, pixel7a.keystoreFeatureVersion)
    }

    private fun evaluate(
        attV: Int?,
        kmV: Int?,
        sdkInt: Int,
        declared: Int,
        release: Boolean = true,
    ) = VersionBounds.evaluate(
        attestationVersion = attV,
        keymasterVersion = kmV,
        securityLevel = AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        declaredKeystoreFeatureVersion = declared,
        sdkInt = sdkInt,
        releaseBuild = release,
        presentsAsPhysicalHardware = true,
    )
}
