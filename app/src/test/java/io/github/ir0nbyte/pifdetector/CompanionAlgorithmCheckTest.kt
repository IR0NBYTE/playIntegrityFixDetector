package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The companion algorithm table.
 *
 * The cases that matter most are the ones that must stay silent. Every device
 * on the bench except the handset lands in one of them, and the emulator case
 * is the one that killed the first draft of this arm.
 */
class CompanionAlgorithmCheckTest {

    private val googleKeys =
        AttestationAnalysis.anchorKeyEncodings(AttestationRoots.pinnedRoots)
    private val softwareKeys =
        AttestationAnalysis.anchorKeyEncodings(SoftwareAttestationRoots.roots)

    private val pinnedRoot = AttestationRoots.pinnedRoots.first()
    private val softwareRoot = SoftwareAttestationRoots.roots.first()

    @Test
    fun aPinnedRootIsRecognisedAsGoogle() {
        assertEquals(
            CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
            CompanionAlgorithmCheck.classifyRoot(pinnedRoot, googleKeys, softwareKeys)
        )
    }

    @Test
    fun anAospRootIsRecognisedAsSoftware() {
        assertEquals(
            CompanionAlgorithmCheck.RootOrigin.AOSP_SOFTWARE,
            CompanionAlgorithmCheck.classifyRoot(softwareRoot, googleKeys, softwareKeys)
        )
    }

    @Test
    fun noChainMeansAbsent() {
        assertEquals(
            CompanionAlgorithmCheck.RootOrigin.ABSENT,
            CompanionAlgorithmCheck.classifyRoot(null, googleKeys, softwareKeys)
        )
    }

    /**
     * A build whose PEMs failed to parse has empty key sets. It must classify
     * everything as unrecognised, which makes every verdict silent, rather than
     * matching vacuously.
     */
    @Test
    fun emptyRootSetsRecogniseNothing() {
        assertEquals(
            CompanionAlgorithmCheck.RootOrigin.UNRECOGNISED,
            CompanionAlgorithmCheck.classifyRoot(pinnedRoot, emptySet(), emptySet())
        )
        assertEquals(
            CompanionAlgorithmCheck.Verdict.NOT_EVALUATED,
            CompanionAlgorithmCheck.evaluate(
                CompanionAlgorithmCheck.RootOrigin.UNRECOGNISED,
                primaryHardwareBacked = true,
                companionOrigin = CompanionAlgorithmCheck.RootOrigin.AOSP_SOFTWARE
            )
        )
    }

    @Test
    fun theFindingIsAGoogleRootedPrimaryBesideASoftwareRootedCompanion() {
        val verdict = CompanionAlgorithmCheck.evaluate(
            CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
            primaryHardwareBacked = true,
            companionOrigin = CompanionAlgorithmCheck.RootOrigin.AOSP_SOFTWARE
        )
        assertEquals(CompanionAlgorithmCheck.Verdict.COMPANION_SOFTWARE_ROOTED, verdict)
        assertTrue(verdict.isFinding)
        assertEquals(DetectionResult.DETECTION_ATTEST_FORGERY, CompanionAlgorithmCheck.mask(verdict))
        assertEquals(
            listOf(CompanionAlgorithmCheck.COMPANION_SOFTWARE_ROOT),
            CompanionAlgorithmCheck.reasons(verdict)
        )
    }

    @Test
    fun bothAlgorithmsGoogleRootedSaysNothing() {
        val verdict = CompanionAlgorithmCheck.evaluate(
            CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
            primaryHardwareBacked = true,
            companionOrigin = CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED
        )
        assertEquals(CompanionAlgorithmCheck.Verdict.AGREED, verdict)
        assertSilent(verdict)
    }

    /**
     * A stock emulator. Both algorithms come from AOSP software roots, and the
     * two roots are not even the same key, so a root-equality rule would have
     * convicted it. The precondition is what keeps this silent.
     */
    @Test
    fun aStockEmulatorServingSoftwareForBothIsNotEvaluated() {
        val verdict = CompanionAlgorithmCheck.evaluate(
            CompanionAlgorithmCheck.RootOrigin.AOSP_SOFTWARE,
            primaryHardwareBacked = false,
            companionOrigin = CompanionAlgorithmCheck.RootOrigin.AOSP_SOFTWARE
        )
        assertEquals(CompanionAlgorithmCheck.Verdict.NOT_EVALUATED, verdict)
        assertSilent(verdict)
    }

    /** A refusal is "could not tell", never a finding. */
    @Test
    fun aKeystoreThatWillNotServeRsaIsNotAFinding() {
        val verdict = CompanionAlgorithmCheck.evaluate(
            CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
            primaryHardwareBacked = true,
            companionOrigin = CompanionAlgorithmCheck.RootOrigin.ABSENT
        )
        assertEquals(CompanionAlgorithmCheck.Verdict.COMPANION_REFUSED, verdict)
        assertSilent(verdict)
    }

    /** A root Google adds tomorrow must read as unfamiliar, not as a forgery. */
    @Test
    fun anUnrecognisedCompanionRootIsReportedAndNotJudged() {
        val verdict = CompanionAlgorithmCheck.evaluate(
            CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
            primaryHardwareBacked = true,
            companionOrigin = CompanionAlgorithmCheck.RootOrigin.UNRECOGNISED
        )
        assertEquals(CompanionAlgorithmCheck.Verdict.COMPANION_UNRECOGNISED, verdict)
        assertSilent(verdict)
    }

    /**
     * A software-level record anchored to a Google root is somebody else's
     * finding, DETECTION_ATTEST_SOFTWARE, and must not also fire here.
     */
    @Test
    fun aGoogleRootedPrimaryThatIsNotHardwareBackedIsNotEvaluated() {
        assertFalse(
            CompanionAlgorithmCheck.worthAsking(
                CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
                primaryHardwareBacked = false
            )
        )
        assertEquals(
            CompanionAlgorithmCheck.Verdict.NOT_EVALUATED,
            CompanionAlgorithmCheck.evaluate(
                CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
                primaryHardwareBacked = false,
                companionOrigin = CompanionAlgorithmCheck.RootOrigin.AOSP_SOFTWARE
            )
        )
    }

    /** The second keygen is only paid for when a contradiction is reachable. */
    @Test
    fun theCompanionIsOnlyRequestedWhenTheContradictionIsReachable() {
        assertTrue(
            CompanionAlgorithmCheck.worthAsking(
                CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED, true
            )
        )
        for (origin in CompanionAlgorithmCheck.RootOrigin.entries) {
            if (origin == CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED) continue
            assertFalse(
                "a $origin primary should not cost an RSA keygen",
                CompanionAlgorithmCheck.worthAsking(origin, true)
            )
        }
    }

    @Test
    fun everyDeclaredCodeIsReachableFromSomeVerdict() {
        val emitted = CompanionAlgorithmCheck.Verdict.entries
            .flatMap { CompanionAlgorithmCheck.reasons(it) }
            .toSet()
        assertEquals(CompanionAlgorithmCheck.REASON_CODES, emitted)
    }

    private fun assertSilent(verdict: CompanionAlgorithmCheck.Verdict) {
        assertFalse(verdict.isFinding)
        assertEquals(0, CompanionAlgorithmCheck.mask(verdict))
        assertEquals(emptyList<Int>(), CompanionAlgorithmCheck.reasons(verdict))
    }
}
