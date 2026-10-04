package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The invariants that the previous set of independent booleans could not hold.
 *
 * Each row carries exactly one state, so the summary buckets partition the rows
 * instead of being three overlapping predicates that each caller re-derived.
 * They had drifted: the list ordered INFORMATIONAL above a row that could not
 * apply, and the summary card ordered them the other way.
 */
class CheckStateTest {

    @Test
    fun theThreeSummaryBucketsPartitionEveryRow() {
        val rows = DetectionResult.fromBitmask(DetectionResult.ALL_FLAGS_MASK)
        val findings = rows.count { it.state.isFinding }
        val unobservable = rows.count { !it.state.isObservable }
        val review = rows.count { it.state.needsReview }
        val passes = rows.count { it.state == CheckState.CLEAN }

        assertEquals(
            "every row must land in exactly one bucket",
            rows.size,
            findings + unobservable + review + passes
        )
    }

    @Test
    fun bucketsAreMutuallyExclusiveForEveryState() {
        for (state in CheckState.entries) {
            val inBuckets = listOf(
                state.isFinding,
                !state.isObservable,
                state.needsReview,
                state == CheckState.CLEAN,
            ).count { it }
            assertEquals("$state belongs to exactly one bucket", 1, inBuckets)
        }
    }

    /** A finding has been resolved, so it is never also awaiting review. */
    @Test
    fun aFindingNeverAlsoNeedsReview() {
        for (state in CheckState.entries) {
            if (state.isFinding) assertFalse("$state", state.needsReview)
        }
    }

    /** Nothing unobservable can need review: there was never anything to see. */
    @Test
    fun anUnobservableStateNeverNeedsReview() {
        for (state in CheckState.entries) {
            if (!state.isObservable) assertFalse("$state", state.needsReview)
        }
    }

    /**
     * A privileged-only check that DID fire is a real finding. Running with
     * root makes it observable, so it must not be filed as unobservable.
     */
    @Test
    fun aPrivilegedOnlyRowThatFiredIsAFinding() {
        val rows = DetectionResult.fromBitmask(DetectionResult.DETECTION_PIF)
        val row = rows.first { it.flag == DetectionResult.DETECTION_PIF }

        assertTrue("privileged-only metadata is kept", row.privilegedOnly)
        assertEquals(CheckState.DETECTED, row.state)
        assertTrue(row.state.isObservable)
    }

    /** The same row, when it did not fire, is not a pass. */
    @Test
    fun aPrivilegedOnlyRowThatDidNotFireIsNotAPass() {
        val rows = DetectionResult.fromBitmask(0)
        val row = rows.first { it.flag == DetectionResult.DETECTION_PIF }

        assertEquals(CheckState.NOT_OBSERVABLE, row.state)
        assertFalse("must never be counted as a pass", row.state == CheckState.CLEAN)
    }

    @Test
    fun aCleanRunHasNoFindingsAndNothingToReview() {
        val rows = DetectionResult.fromBitmask(0)
        assertEquals(0, rows.count { it.state.isFinding })
        assertEquals(0, rows.count { it.state.needsReview })
    }

    /**
     * The derived booleans are what the pre-CheckState callers and tests still
     * read, so they have to keep agreeing with the state they come from.
     */
    @Test
    fun derivedBooleansAgreeWithTheState() {
        val rows = DetectionResult.fromBitmask(DetectionResult.ALL_FLAGS_MASK) +
            DetectionResult.fromBitmask(0)

        for (row in rows) {
            assertEquals(row.state == CheckState.DETECTED, row.detected)
            assertEquals(row.state == CheckState.INFORMATIONAL, row.warning)
            assertEquals(
                row.state == CheckState.UNVERIFIABLE || row.state == CheckState.SKIPPED,
                row.inconclusive
            )
            assertTrue(
                "notApplicable implies the row is unobservable",
                !row.notApplicable || !row.state.isObservable
            )
            assertFalse(
                "a privileged-only row is unobservable rather than inapplicable",
                row.notApplicable && row.privilegedOnly
            )
        }
    }

    /** No row may be left without a state by a path through fromBitmask. */
    @Test
    fun everyRowHasAState() {
        val rows = DetectionResult.fromBitmask(0) +
            DetectionResult.fromBitmask(DetectionResult.ALL_FLAGS_MASK)
        assertTrue(rows.isNotEmpty())
        assertTrue(rows.all { it.state in CheckState.entries })
    }
}
