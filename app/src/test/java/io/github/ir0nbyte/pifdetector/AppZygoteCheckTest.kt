package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The reason 906 decision table. The finding is a mount reason the isolated
 * child saw and the main process did not; every other row is silence.
 */
class AppZygoteCheckTest {

    private val hider = DetectionResult.DETECTION_ROOT_HIDER

    private fun assertSilent(what: String, main: List<Int>, child: List<Int>?) {
        val v = AppZygoteCheck.evaluate(main, child)
        assertFalse(what, v.isFinding)
        assertEquals(what, 0, v.mask)
        assertEquals(what, emptyList<Int>(), v.reasons)
    }

    private fun assertFires(what: String, main: List<Int>, child: List<Int>) {
        val v = AppZygoteCheck.evaluate(main, child)
        assertTrue(what, v.isFinding)
        assertEquals(what, hider, v.mask)
        assertEquals(what, listOf(906), v.reasons)
    }

    @Test
    fun aChildThatCouldNotBeObservedIsSilence() {
        assertSilent("null child, clean main", emptyList(), null)
        assertSilent("null child, main saw 905", listOf(905), null)
    }

    @Test
    fun anEmptyChildIsSilence() {
        assertSilent("both empty", emptyList(), emptyList())
        assertSilent("main saw more than the child", listOf(901, 902, 905), emptyList())
    }

    @Test
    fun aChildThatSeesOnlyWhatMainSawIsSilence() {
        assertSilent("same single", listOf(905), listOf(905))
        assertSilent("same all three", listOf(901, 902, 905), listOf(905, 902, 901))
        assertSilent("child a subset", listOf(201, 901, 905, 1205), listOf(901))
    }

    @Test
    fun oneMountReasonOnlyTheChildSawFires() {
        for (code in listOf(901, 902, 905)) {
            assertFires("$code only in child", emptyList(), listOf(code))
            assertFires("$code beside unrelated main reasons", listOf(201, 304, 811), listOf(code))
        }
        assertFires("one extra beside a shared one", listOf(905), listOf(905, 901))
        assertFires("the Pixel 7a shape", listOf(304), listOf(901, 905))
    }

    @Test
    fun codesOutsideTheThreeAreIgnored() {
        assertSilent("903 is not compared", emptyList(), listOf(903))
        assertSilent("904 is not compared", emptyList(), listOf(904))
        assertSilent("309 is not compared", emptyList(), listOf(309))
        assertSilent("906 cannot feed itself", emptyList(), listOf(906))
        assertSilent("garbage", emptyList(), listOf(-1, 0, 99999))
        assertFires("an ignored code beside a real one", emptyList(), listOf(903, 902))
    }

    @Test
    fun aFindingIsReportedOnceHoweverManyCodesDiffer() {
        val v = AppZygoteCheck.evaluate(emptyList(), listOf(901, 902, 905, 905))
        assertEquals(listOf(906), v.reasons)
    }

    @Test
    fun theCheckOwnsExactly906() {
        assertEquals(setOf(906), AppZygoteCheck.REASON_CODES)
        assertEquals(hider, ReasonCodes.flagOf(906))
    }
}
