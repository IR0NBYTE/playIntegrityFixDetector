package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The reason codes a run can emit and the Kotlin text table have to agree.
 *
 * A report carries raw integers, so a code something emits but this table has
 * no text for produces a report that says a check fired and cannot say why, and
 * a code nothing can emit is text that can never appear. Neither fails anything
 * at runtime, which is exactly why it needs a build-time guard.
 *
 * There are three producers. The native engine declares its codes in
 * native-lib.cpp, read here as source rather than trusted to be edited
 * alongside, the same approach as RootManagerQueriesSyncTest. The keystore
 * boundary probe and the attested identity probe run in Kotlin because their
 * requests are framework API calls, so each declares its own codes in a
 * REASON_CODES set. All three sets must stay pairwise disjoint, because a code
 * identifies one arm.
 */
class ReasonCodesSyncTest {

    @Test
    fun everyNativeReasonCodeHasText() {
        val native = nativeReasonCodes()
        assertTrue("no reason constants parsed out of native-lib.cpp", native.isNotEmpty())

        val missing = native.values.sorted() - ReasonCodes.knownCodes
        assertEquals(
            "the engine can emit these codes but ReasonCodes has no text for them, " +
                "so a report would say a check fired without saying why: $missing",
            emptyList<Int>(),
            missing
        )
    }

    @Test
    fun everyProbeReasonCodeHasText() {
        for ((probe, codes) in KOTLIN_PRODUCERS) {
            val missing = codes.sorted() - ReasonCodes.knownCodes
            assertEquals(
                "$probe can emit these codes but ReasonCodes has no text for them: $missing",
                emptyList<Int>(),
                missing
            )
        }
    }

    @Test
    fun noKotlinTextForACodeNothingCanEmit() {
        val emittable = nativeReasonCodes().values.toSet() + kotlinReasonCodes()
        val orphaned = ReasonCodes.knownCodes.sorted().filterNot { it in emittable }
        assertEquals(
            "these codes have text but no producer, so the text is unreachable: $orphaned",
            emptyList<Int>(),
            orphaned
        )
    }

    /** A code names one arm, so no two producers may both claim it. */
    @Test
    fun theProducersDoNotShareACode() {
        val producers = listOf("the native engine" to nativeReasonCodes().values.toSet()) +
            KOTLIN_PRODUCERS
        for (i in producers.indices) {
            for (j in i + 1 until producers.size) {
                val shared = producers[i].second.intersect(producers[j].second)
                assertEquals(
                    "a code claimed by both ${producers[i].first} and " +
                        "${producers[j].first}: $shared",
                    emptySet<Int>(),
                    shared
                )
            }
        }
    }

    private fun kotlinReasonCodes(): Set<Int> =
        KOTLIN_PRODUCERS.flatMapTo(HashSet()) { it.second }

    /**
     * A new Kotlin probe that declares codes but is left out of
     * [KOTLIN_PRODUCERS] would slip past every check above, because its codes
     * would simply not be looked at. Anything with text and no native producer
     * is owned by a Kotlin probe, so the two sets have to be the same set.
     */
    @Test
    fun everyKotlinProducerIsListed() {
        val native = nativeReasonCodes().values.toSet()
        val nonNative = ReasonCodes.knownCodes.filterNot { it in native }.toSet()
        assertEquals(
            "these codes have text and no native producer, so a Kotlin probe owns " +
                "them and was not added to KOTLIN_PRODUCERS",
            nonNative,
            kotlinReasonCodes()
        )
    }

    /** Codes are append-only, so two constants must never share a value. */
    @Test
    fun nativeReasonCodesAreUnique() {
        val native = nativeReasonCodes()
        val duplicates = native.values
            .groupingBy { it }.eachCount()
            .filterValues { it > 1 }
            .keys
        assertEquals("reason codes reused: $duplicates", emptySet<Int>(), duplicates)
    }

    /**
     * The grouping is load bearing: the hundreds digit routes a code to its
     * row, so a code must sit in the family of the flag its text names.
     */
    @Test
    fun everyCodeSitsInTheFamilyOfItsFlag() {
        val byFamily = ReasonCodes.describe(ReasonCodes.knownCodes.toList())
        for ((flag, texts) in byFamily) {
            assertTrue("code routed to the unattributed bucket: $texts", flag != ReasonCodes.UNATTRIBUTED)
        }
        assertEquals(
            "every known code should route to a flag",
            ReasonCodes.knownCodes.size,
            byFamily.values.sumOf { it.size }
        )
    }

    @Test
    fun anUnknownCodeIsKeptRatherThanDropped() {
        val described = ReasonCodes.describe(listOf(999_999))
        assertEquals(1, described.size)
        assertTrue(described.containsKey(ReasonCodes.UNATTRIBUTED))
    }

    @Test
    fun aReasonLandsOnTheRowItExplains() {
        val rows = DetectionResult.fromBitmask(
            DetectionResult.DETECTION_BOOTLOADER,
            reasonCodes = listOf(504),
        )
        val bootloader = rows.first { it.flag == DetectionResult.DETECTION_BOOTLOADER }
        assertEquals(1, bootloader.reasons.size)
        assertTrue(bootloader.reasons.single().contains("flash.locked"))

        assertTrue(
            "a reason must not leak onto rows it does not explain",
            rows.filter { it.flag != DetectionResult.DETECTION_BOOTLOADER }
                .all { it.reasons.isEmpty() }
        )
    }

    /** Several arms of one check each get their own line. */
    @Test
    fun everyArmThatFiredIsListed() {
        val rows = DetectionResult.fromBitmask(
            DetectionResult.DETECTION_BOOTLOADER,
            reasonCodes = listOf(501, 504, 506),
        )
        val bootloader = rows.first { it.flag == DetectionResult.DETECTION_BOOTLOADER }
        assertEquals(3, bootloader.reasons.size)
    }

    /** A check with no reasons wired renders exactly as it did before. */
    @Test
    fun rowsWithoutReasonsAreUnchanged() {
        val rows = DetectionResult.fromBitmask(DetectionResult.DETECTION_TREAT_WHEEL)
        assertTrue(rows.all { it.reasons.isEmpty() })
    }

    private fun nativeReasonCodes(): Map<String, Int> {
        val src = repoFile("src/main/cpp/native-lib.cpp").readText()
        val block = Regex("""namespace reason \{(.*?)\n\}""", RegexOption.DOT_MATCHES_ALL)
            .find(src)?.groupValues?.get(1)
            ?: error("could not locate the reason namespace in native-lib.cpp")
        return Regex("""constexpr jint (k\w+)\s*=\s*(\d+);""")
            .findAll(block)
            .associate { it.groupValues[1] to it.groupValues[2].toInt() }
    }

    private companion object {
        val KOTLIN_PRODUCERS: List<Pair<String, Set<Int>>> = listOf(
            "the keystore boundary probe" to KeystoreBoundary.REASON_CODES,
            "the attested identity probe" to AttestedIdentity.REASON_CODES,
        )
    }

    private fun repoFile(relative: String): File {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            for (candidate in listOf(File(dir, relative), File(dir, "app/$relative"))) {
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        error("could not locate $relative from ${File("").absolutePath}")
    }
}
