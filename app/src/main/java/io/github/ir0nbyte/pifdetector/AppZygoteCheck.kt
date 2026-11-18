package io.github.ir0nbyte.pifdetector

/**
 * The decision for reason 906: root mounts hidden from this app but visible
 * from an isolated helper process forked from its own app zygote.
 *
 * A DenyList hider reverts the root mounts in the app's process. Measured on a
 * rooted Pixel 7a (Magisk 28.1, Zygisk, DenyList, Shamiko), the app saw a
 * cleaned table while its isolated child, forked from the app zygote, still
 * saw tmpfs magisk on /debug_ramdisk, /system/bin, /system/lib and
 * /system/lib64. On a stock moto g04 the child's table was the main one minus
 * eight lines and held nothing the main one lacked.
 *
 * Both sides run the same native classifier, and only its three mount
 * reasons are compared. The finding is the difference: the child seeing a
 * mount reason the main process did not. Everything else is silence, never a
 * finding: no child answer, an empty answer, or an answer the main process
 * already explains.
 *
 * Deliberately Android-free and side-effect-free so the whole table is unit
 * testable. [AppZygoteProbe] does the binding and hands the answer here.
 */
object AppZygoteCheck {

    const val REASON_HIDDEN_FROM_APP_ONLY = 906

    /** The mount reasons the child is asked about; anything else is ignored. */
    val COMPARED_REASONS: Set<Int> = setOf(901, 902, 905)

    data class Verdict(val mask: Int, val reasons: List<Int>) {
        val isFinding: Boolean get() = mask != 0
    }

    val CLEAN = Verdict(0, emptyList())

    /**
     * @param mainReasons every reason the main process's engine noted this run.
     * @param childReasons what the isolated child reported, or null when it
     *   could not be observed at all.
     */
    fun evaluate(mainReasons: Collection<Int>, childReasons: Collection<Int>?): Verdict {
        if (childReasons == null) return CLEAN
        val onlyInChild = childReasons
            .filter { it in COMPARED_REASONS }
            .filter { it !in mainReasons }
        if (onlyInChild.isEmpty()) return CLEAN
        return Verdict(DetectionResult.DETECTION_ROOT_HIDER, listOf(REASON_HIDDEN_FROM_APP_ONLY))
    }

    /**
     * Every code this check can emit. [ReasonCodesSyncTest] unions this with
     * the other producers.
     */
    val REASON_CODES: Set<Int> = setOf(REASON_HIDDEN_FROM_APP_ONLY)
}
