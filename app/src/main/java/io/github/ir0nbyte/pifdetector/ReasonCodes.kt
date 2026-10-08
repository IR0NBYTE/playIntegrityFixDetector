package io.github.ir0nbyte.pifdetector

/**
 * Human text for the reason codes the native engine returns beside the bitmask.
 *
 * A detection used to be a lit row and nothing else, so the only way to learn
 * which needle, property or path actually fired was to attach a debugger to the
 * device that showed it. A code says which arm spoke, and the user can put that
 * in a bug report.
 *
 * The codes are grouped by the flag they belong to, family * 100 + member, so a
 * code routes to its row without a second table. They are append-only: a report
 * carries raw integers, so reusing a number would relabel every report already
 * filed against it.
 *
 * [ReasonCodesSyncTest] reads the constants straight out of native-lib.cpp and
 * fails the build if this table and the engine disagree.
 */
object ReasonCodes {

    data class Reason(val code: Int, val flag: Int, val text: String)

    private val TABLE: List<Reason> = listOf(
        Reason(101, DetectionResult.DETECTION_DEBUGGER,
            "TracerPid in /proc/self/status is not zero"),
        Reason(102, DetectionResult.DETECTION_DEBUGGER,
            "The application manifest carries the debuggable flag"),

        Reason(201, DetectionResult.DETECTION_FRIDA,
            "Something is listening on 127.0.0.1:27042"),
        Reason(202, DetectionResult.DETECTION_FRIDA,
            "Something is listening on 127.0.0.1:27043"),
        Reason(203, DetectionResult.DETECTION_FRIDA,
            "A frida socket appears in the process network table"),
        Reason(204, DetectionResult.DETECTION_FRIDA,
            "A thread in this process is named after a frida worker"),
        Reason(205, DetectionResult.DETECTION_FRIDA,
            "A frida agent or gadget library is mapped into this process"),
        Reason(206, DetectionResult.DETECTION_FRIDA,
            "The parent process command line names frida"),

        Reason(301, DetectionResult.DETECTION_ZYGISK,
            "A Zygisk or root-hider library is mapped into this process"),
        Reason(302, DetectionResult.DETECTION_ZYGISK,
            "A Zygisk or Magisk environment variable is set"),
        Reason(303, DetectionResult.DETECTION_ZYGISK,
            "A Magisk Zygisk property is set"),
        Reason(304, DetectionResult.DETECTION_ZYGISK,
            "A root manager module directory is reachable"),
        Reason(305, DetectionResult.DETECTION_ZYGISK,
            "An su binary is present on a system path"),
        Reason(306, DetectionResult.DETECTION_ZYGISK,
            "A busybox binary is present on a system path"),
        Reason(307, DetectionResult.DETECTION_ZYGISK,
            "A legacy SuperUser or SuperSU artefact is present in /system"),
        Reason(308, DetectionResult.DETECTION_ZYGISK,
            "A known root manager package is installed"),

        Reason(501, DetectionResult.DETECTION_BOOTLOADER,
            "ro.boot.verifiedbootstate is not green"),
        Reason(502, DetectionResult.DETECTION_BOOTLOADER,
            "ro.boot.bootloader reports an unlocked state"),
        Reason(503, DetectionResult.DETECTION_BOOTLOADER,
            "ro.boot.veritymode is disabled"),
        Reason(504, DetectionResult.DETECTION_BOOTLOADER,
            "ro.boot.flash.locked is zero"),
        Reason(505, DetectionResult.DETECTION_BOOTLOADER,
            "ro.boot.vbmeta.device_state is not locked"),
        Reason(506, DetectionResult.DETECTION_BOOTLOADER,
            "ro.debuggable is set"),
        Reason(507, DetectionResult.DETECTION_BOOTLOADER,
            "ro.secure is off"),
        Reason(508, DetectionResult.DETECTION_BOOTLOADER,
            "sys.oem_unlock_allowed is set, which is the developer toggle " +
                "rather than proof the bootloader is open"),

        Reason(801, DetectionResult.DETECTION_PROP_SPOOF,
            "The fingerprint's brand does not match ro.product.brand"),
        Reason(802, DetectionResult.DETECTION_PROP_SPOOF,
            "The build type and tags contradict the fingerprint"),
        Reason(803, DetectionResult.DETECTION_PROP_SPOOF,
            "ro.build.flavor contradicts a production build claim"),
        Reason(804, DetectionResult.DETECTION_PROP_SPOOF,
            "Property reads were slow enough to suggest a hook"),
        Reason(805, DetectionResult.DETECTION_PROP_SPOOF,
            "The board claims a Pixel while the kernel reports other silicon"),

        Reason(1001, DetectionResult.DETECTION_CODE_INTEGRITY,
            "A libc function begins with a jump into memory that is not a " +
                "recognised code source"),
        Reason(1002, DetectionResult.DETECTION_CODE_INTEGRITY,
            "An executable mapping comes from somewhere the platform never " +
                "loads code from"),
        Reason(1003, DetectionResult.DETECTION_CODE_INTEGRITY,
            "A GOT entry points outside the library that owns it"),
        Reason(1004, DetectionResult.DETECTION_CODE_INTEGRITY,
            "The in-memory text of a library differs from the file on disk, " +
                "which corroborates a hook rather than proving one"),

        Reason(901, DetectionResult.DETECTION_ROOT_HIDER,
            "A tmpfs shadows a read-only system partition"),
        Reason(902, DetectionResult.DETECTION_ROOT_HIDER,
            "A bind mount is rooted under /adb on the userdata device"),
        Reason(903, DetectionResult.DETECTION_ROOT_HIDER,
            "An overlay is mounted over /system"),
        Reason(904, DetectionResult.DETECTION_ROOT_HIDER,
            "More read-write-execute anonymous mappings than ART alone explains"),
    )

    private val BY_CODE: Map<Int, Reason> = TABLE.associateBy { it.code }

    /** Every code this build knows how to explain. */
    val knownCodes: Set<Int> get() = BY_CODE.keys

    /**
     * Reason text per flag, for the codes this run returned. An unknown code is
     * kept rather than dropped, so a report from a newer engine against an
     * older string table still shows that something fired.
     */
    fun describe(codes: List<Int>): Map<Int, List<String>> {
        val out = LinkedHashMap<Int, MutableList<String>>()
        for (code in codes.distinct()) {
            val reason = BY_CODE[code]
            if (reason != null) {
                out.getOrPut(reason.flag) { mutableListOf() }.add(reason.text)
            } else {
                out.getOrPut(UNATTRIBUTED) { mutableListOf() }
                    .add("Unrecognised reason code $code")
            }
        }
        return out
    }

    /** Bucket for codes this build has no text for. */
    const val UNATTRIBUTED = 0
}
