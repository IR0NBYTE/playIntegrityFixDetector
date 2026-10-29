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
 * There are five producers. The native engine declares its codes in
 * native-lib.cpp, read here as source rather than trusted to be edited
 * alongside, the same approach as RootManagerQueriesSyncTest. The keystore
 * boundary, attested identity, StrongBox and companion algorithm probes run in
 * Kotlin because their requests are framework API calls, so each declares its
 * own codes in a REASON_CODES set. All five sets must stay pairwise disjoint,
 * because a code identifies one arm.
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

    /**
     * A constant that no arm ever passes to reason::note is a code that can
     * never reach a report, so the family can set its bit and leave the reader
     * a red row with nothing under it to read.
     *
     * This is the same defect PR #20 fixed for the property walk, where the
     * walk returned at its first finding and 801 to 805 never reached a report.
     * It was found again on 2026-10-26 with thirteen of the thirty-eight native
     * codes declared and never emitted: the whole frida family, four of the
     * zygisk arms and all four mount and hider arms. A phone running
     * frida-server reported DETECTED and said nothing about why.
     *
     * Declaring the constant is not the producer. Calling note is.
     */
    @Test
    fun everyNativeReasonCodeIsEmittedBySomeArm() {
        val src = repoFile("src/main/cpp/native-lib.cpp").readText()
        val emitted = Regex("""reason::note\(\s*reason::(k\w+)""")
            .findAll(src)
            .map { it.groupValues[1] }
            .toSet()
        assertTrue("no reason::note call sites parsed out of native-lib.cpp", emitted.isNotEmpty())

        val declared = nativeReasonCodes()
        val unreachable = declared.filterKeys { it !in emitted }
        assertTrue(
            "these native codes are declared but never passed to reason::note, so " +
                "nothing can ever report them: $unreachable",
            unreachable.isEmpty(),
        )
    }

    /**
     * A flag a run can set, with no reason code anywhere able to explain it,
     * is a red row with nothing underneath to read.
     */
    @Test
    fun everyFlagThatCanFireHasAReasonOrIsListedAsHavingNone() {
        val covered = ReasonCodes.flagsWithText
        val uncovered = allFlags().filterNot { it in covered || it in FLAGS_WITH_NO_REASONS_YET }
        assertEquals(
            "these flags can be set with nothing able to explain them: " + uncovered.map(::hex),
            emptyList<Int>(),
            uncovered,
        )

        val stale = FLAGS_WITH_NO_REASONS_YET.filter { it in covered }
        assertEquals(
            "these flags now have reason text and should come off the list: " + stale.map(::hex),
            emptyList<Int>(),
            stale,
        )
    }

    /**
     * The direction that actually protects a reader, and the one every other
     * check in this file is blind to.
     *
     * [everyNativeReasonCodeIsEmittedBySomeArm] proves a declared constant has
     * a call site somewhere. A family having call sites says nothing about the
     * one arm that forgot. On 2026-10-29 the module needle loop in
     * detectMountArtifacts set DETECTION_ZYGISK with no note of its own and
     * every check here passed, because 301 to 308 were already wired by other
     * arms. A phone whose only root signal was a mounted zygisk module
     * reported the flag and explained nothing.
     *
     * So this reads the engine as source. Any function that sets a detection
     * bit itself must be able to reach a reason code in that bit's family,
     * either noted in its own body or in something it calls. Reasons do not
     * travel back down from a caller, because that is what hid this defect:
     * the arm beside it had already satisfied the family.
     */
    @Test
    fun everyArmThatSetsABitCanReachAReasonForIt() {
        val src = repoFile("src/main/cpp/native-lib.cpp").readText()
        val codes = nativeReasonCodes()
        val bodies = nativeFunctionBodies(src)
        assertTrue("too few function bodies parsed: ${bodies.size}", bodies.size > 40)
        for (expected in listOf("detectMountArtifacts", "detectSuBinary", "classifyMountLine")) {
            assertTrue("the source walk lost $expected", expected in bodies)
        }

        val noteCall = Regex("""reason::note\(\s*reason::(k\w+)""")
        val notedIn = bodies.mapValues { (_, body) ->
            noteCall.findAll(body).mapNotNull { codes[it.groupValues[1]] }.toSet()
        }
        val callsIn = bodies.mapValues { (name, body) ->
            Regex("""\b([A-Za-z_]\w*)\s*\(""").findAll(body)
                .map { it.groupValues[1] }
                .filterTo(HashSet()) { it in bodies && it != name }
        }

        // Codes each function can reach, through calls of any depth.
        fun reachableFrom(start: String): Set<Int> {
            val seen = HashSet<String>()
            val out = HashSet<Int>()
            val queue = ArrayDeque(listOf(start))
            while (queue.isNotEmpty()) {
                val cur = queue.removeFirst()
                if (!seen.add(cur)) continue
                out += notedIn[cur].orEmpty()
                queue += callsIn[cur].orEmpty()
            }
            return out
        }

        val callers = HashMap<String, MutableSet<String>>()
        for ((name, called) in callsIn) for (c in called) {
            callers.getOrPut(c) { HashSet() } += name
        }

        val complaints = mutableListOf<String>()
        for ((name, body) in bodies) {
            val explained = HashSet<Int>()
            reachableFrom(name).mapNotNullTo(explained) { ReasonCodes.flagOf(it) }
            if (name in CLASSIFIERS_WHOSE_CALLER_NOTES) {
                for (up in callers[name].orEmpty()) {
                    reachableFrom(up).mapNotNullTo(explained) { ReasonCodes.flagOf(it) }
                }
            }
            if (name in AGGREGATES) continue
            for (bit in bitsSetIn(body)) {
                if (bit in FLAGS_WITH_NO_REASONS_YET || bit in explained) continue
                complaints += "$name sets ${hex(bit)} and can reach no reason in that family"
            }
        }
        assertEquals(complaints.joinToString("; "), emptyList<String>(), complaints)
    }

    /** Detection bits a body sets, as opposed to merely naming one. */
    private fun bitsSetIn(body: String): Set<Int> =
        Regex("""(?:\|=|\breturn\b|\|)\s*(DETECTION_\w+)""").findAll(body)
            .mapNotNull { DETECTION_BITS[it.groupValues[1]] }
            .toSet()

    /**
     * Function bodies by name.
     *
     * Brace depth alone is not enough, because a namespace or a struct opens
     * one and holds the functions inside it. Those scopes are transparent
     * here: the depth they add becomes the new floor, so a function declared
     * inside propa or codeint is found the same as one at file scope. A lambda
     * in the dispatch table stays part of the function holding the table,
     * which is what the call walk above wants.
     */
    private fun nativeFunctionBodies(src: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val transparent = Regex("""^\s*(namespace|struct|class|union|enum)\b""")
        val signature = Regex("""([A-Za-z_]\w*)\s*\(""")
        var depth = 0
        var floor = 0
        var name: String? = null
        var pending: String? = null
        var bodyDepth = 0
        val body = StringBuilder()
        for (line in src.lines()) {
            val code = line.substringBefore("//")
            val delta = code.count { it == '{' } - code.count { it == '}' }
            if (name != null) {
                body.appendLine(line)
                depth += delta
                if (depth <= bodyDepth) {
                    out[name] = body.toString()
                    body.setLength(0)
                    name = null
                }
                continue
            }
            val trimmed = code.trim()
            if (depth == floor && trimmed.isNotEmpty() && !trimmed.startsWith("#")) {
                if (pending == null && transparent.containsMatchIn(trimmed)) {
                    depth += delta
                    if (delta > 0) floor = depth
                    continue
                }
                signature.find(trimmed)?.let { pending = it.groupValues[1] }
                if (pending != null) {
                    // A signature can run over several lines, so hold the name
                    // until the body opens or a semicolon says it was only a
                    // declaration.
                    if (delta > 0) {
                        name = pending
                        pending = null
                        bodyDepth = depth
                        depth += delta
                        body.setLength(0)
                        body.appendLine(line)
                        continue
                    }
                    if (trimmed.endsWith(";") || delta < 0) pending = null
                    depth += delta
                    continue
                }
            }
            depth += delta
            if (depth < floor) floor = depth
        }
        return out
    }

    private fun allFlags(): List<Int> = (0 until Int.SIZE_BITS - 1)
        .map { 1 shl it }
        .filter { it and DetectionResult.ALL_FLAGS_MASK != 0 }

    private fun hex(bit: Int) = "0x" + Integer.toHexString(bit)

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
        /**
         * Flags no reason code explains yet. Each renders as a row with no
         * line under it, which is honest only while the check behind it is a
         * single yes or no with nothing to choose between. Listing one here is
         * the deliberate act that forgetting a reason is not.
         */
        val FLAGS_WITH_NO_REASONS_YET: Set<Int> = setOf(
            DetectionResult.DETECTION_PIF,
            DetectionResult.DETECTION_SIGNATURE,
            DetectionResult.DETECTION_TRICKYSTORE,
            DetectionResult.DETECTION_PIF_STREAM,
            DetectionResult.DETECTION_CANARY_FP,
            DetectionResult.DETECTION_TSEE,
            DetectionResult.DETECTION_PIF_RUST,
            DetectionResult.DETECTION_TREAT_WHEEL,
            DetectionResult.DETECTION_ATTEST_ANOMALY,
            DetectionResult.DETECTION_ATTEST_REVOKED,
            DetectionResult.DETECTION_ATTEST_CROSS_SOURCE,
            DetectionResult.DETECTION_ATTEST_SOFTWARE,
            DetectionResult.DETECTION_ATTEST_VALIDITY,
            DetectionResult.DETECTION_ATTEST_VERSION,
            DetectionResult.DETECTION_ATTEST_SHAPE,
            DetectionResult.DETECTION_ATTEST_MODULE_HASH,
        )

        /** Native bit names, so the source walk can resolve what it reads. */
        val DETECTION_BITS: Map<String, Int> = mapOf(
            "DETECTION_DEBUGGER" to DetectionResult.DETECTION_DEBUGGER,
            "DETECTION_FRIDA" to DetectionResult.DETECTION_FRIDA,
            "DETECTION_ZYGISK" to DetectionResult.DETECTION_ZYGISK,
            "DETECTION_BOOTLOADER" to DetectionResult.DETECTION_BOOTLOADER,
            "DETECTION_PROP_SPOOF" to DetectionResult.DETECTION_PROP_SPOOF,
            "DETECTION_ROOT_HIDER" to DetectionResult.DETECTION_ROOT_HIDER,
            "DETECTION_CODE_INTEGRITY" to DetectionResult.DETECTION_CODE_INTEGRITY,
        )

        /**
         * Pure classifiers that return a bit and deliberately note nothing, so
         * the self test can drive them over fixtures without a reason buffer.
         * Their caller turns the rule they matched into the reason, so for
         * these one the caller can reach counts.
         */
        val CLASSIFIERS_WHOSE_CALLER_NOTES: Set<String> = setOf("classifyMountLine")

        /**
         * Names every bit without claiming one: the mask the Kotlin layer asks
         * for so it can tell a flag this build knows from one it does not.
         */
        val AGGREGATES: Set<String> = setOf("nativeAllFlagsMaskImpl")

        val KOTLIN_PRODUCERS: List<Pair<String, Set<Int>>> = listOf(
            "the keystore boundary probe" to KeystoreBoundary.REASON_CODES,
            "the attested identity probe" to AttestedIdentity.REASON_CODES,
            "the StrongBox probe" to StrongBoxCheck.REASON_CODES,
            "the companion algorithm probe" to CompanionAlgorithmCheck.REASON_CODES,
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
