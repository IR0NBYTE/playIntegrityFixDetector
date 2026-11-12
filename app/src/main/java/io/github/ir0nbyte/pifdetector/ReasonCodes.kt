package io.github.ir0nbyte.pifdetector

/**
 * Human text for the reason codes a run produces beside the bitmask.
 *
 * Most come from the native engine. The 1100 family comes from
 * [KeystoreBoundary], [AttestedIdentity], [StrongBoxCheck],
 * [CompanionAlgorithmCheck] and [ActiveAttestationProbe], and the 1200 family
 * from [KeyAttestationProbe]. Those run in Kotlin because the requests they
 * make are framework API calls, so [ReasonCodesSyncTest] checks this table
 * against all seven producers rather than against native-lib.cpp alone.
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
            "An su binary is present on a path only root can create"),
        Reason(306, DetectionResult.DETECTION_ZYGISK,
            "A busybox binary is present on a path only root can create"),
        Reason(307, DetectionResult.DETECTION_ZYGISK,
            "A legacy SuperUser or SuperSU artefact is present in /system"),
        Reason(308, DetectionResult.DETECTION_ZYGISK,
            "A known root manager package is installed"),
        Reason(309, DetectionResult.DETECTION_ZYGISK,
            "A Zygisk module is bind mounted into this process"),

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
        Reason(806, DetectionResult.DETECTION_PROP_SPOOF,
            "A /dev/__properties__ area is mapped private rather than shared"),

        Reason(807, DetectionResult.DETECTION_PROP_SPOOF,
            "A property area holds wiped allocations its own trie cannot reach"),

        Reason(808, DetectionResult.DETECTION_PROP_SPOOF,
            "A property name sits out of order in the trie that indexes it"),
        Reason(809, DetectionResult.DETECTION_PROP_SPOOF,
            "A property's name disagrees with the trie path that reaches it"),

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

        Reason(1101, DetectionResult.DETECTION_ATTEST_FORGERY,
            "A key generated with no attestation challenge came back carrying " +
                "an attestation record"),
        Reason(1102, DetectionResult.DETECTION_ATTEST_FORGERY,
            "A signing key generated with no attestation challenge came back " +
                "without a self-signed certificate"),
        Reason(1103, DetectionResult.DETECTION_ATTEST_FORGERY,
            "An attestation challenge past the documented 128 byte maximum was " +
                "accepted instead of refused"),
        Reason(1104, DetectionResult.DETECTION_ATTEST_FORGERY,
            "That over-limit request was served from software while a legal one " +
                "was served from hardware"),

        Reason(1105, DetectionResult.DETECTION_ATTEST_FORGERY,
            "An ordinary attestation record carried a device identifier that " +
                "nothing asked it to attest"),
        Reason(1106, DetectionResult.DETECTION_ATTEST_FORGERY,
            "An attestation record carried a privileged identifier this app " +
                "cannot request"),
        Reason(1107, DetectionResult.DETECTION_ATTEST_FORGERY,
            "A request to attest the device properties was accepted and then " +
                "attested no identifier at all"),
        Reason(1108, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The attested identifiers sit where the Android system puts its own " +
                "entries, not where the secure environment vouches for them"),

        Reason(1109, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The keystore has no StrongBox instance, yet it reported an " +
                "ordinary key as living in one"),
        Reason(1110, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The keystore has no StrongBox instance, yet an attestation record " +
                "claims StrongBox"),
        Reason(1111, DetectionResult.DETECTION_ATTEST_FORGERY,
            "A StrongBox key was served on a device whose own feature list " +
                "declares no StrongBox"),
        Reason(1112, DetectionResult.DETECTION_ATTEST_FORGERY,
            "StrongBox accepted a 192 bit AES key, a size the HAL says a " +
                "secure element must not support"),

        Reason(1113, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The same keystore served a Google-rooted hardware chain for one " +
                "key algorithm and the AOSP software fallback for the other"),

        Reason(1114, DetectionResult.DETECTION_ATTEST_FORGERY,
            "An attestation key request came back as a single self-signed " +
                "certificate instead of a chain"),
        Reason(1115, DetectionResult.DETECTION_ATTEST_FORGERY,
            "In the attestation key chain, a certificate does not verify " +
                "against the one that issued it"),
        Reason(1116, DetectionResult.DETECTION_ATTEST_FORGERY,
            "In the attestation key chain, a certificate was issued by " +
                "something that is not a certificate authority"),
        Reason(1117, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The attestation key record does not carry the challenge that " +
                "was asked for"),
        Reason(1118, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The attestation key chain claims hardware but is not anchored to " +
                "a published Google root, while the ordinary chain was clean"),
        Reason(1119, DetectionResult.DETECTION_ATTEST_FORGERY,
            "An authentication-bound key request came back as a single " +
                "self-signed certificate instead of a chain"),
        Reason(1120, DetectionResult.DETECTION_ATTEST_FORGERY,
            "In the authentication-bound key chain, a certificate does not " +
                "verify against the one that issued it"),
        Reason(1121, DetectionResult.DETECTION_ATTEST_FORGERY,
            "In the authentication-bound key chain, a certificate was issued " +
                "by something that is not a certificate authority"),
        Reason(1122, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The authentication-bound key's certificate signature follows the " +
                "SHA-512 digest requested for the key itself"),
        Reason(1123, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The authentication-bound key record does not carry the challenge " +
                "that was asked for"),
        Reason(1124, DetectionResult.DETECTION_ATTEST_FORGERY,
            "The authentication-bound key record says no user authentication " +
                "is required, although the request required it"),

        Reason(1201, DetectionResult.DETECTION_ATTEST_ANOMALY,
            "A certificate in the attestation chain does not verify against " +
                "the one that issued it"),
        Reason(1202, DetectionResult.DETECTION_ATTEST_ANOMALY,
            "A certificate in the attestation chain was issued by something " +
                "that is not a certificate authority"),
        Reason(1203, DetectionResult.DETECTION_ATTEST_ANOMALY,
            "The attestation chain is neither software backed nor anchored to " +
                "a published Google root"),
        Reason(1204, DetectionResult.DETECTION_ATTEST_ANOMALY,
            "The attested challenge is not the one that was asked for"),
        Reason(1205, DetectionResult.DETECTION_ATTEST_ANOMALY,
            "The attested root of trust claims a verified boot while the " +
                "device shows root hiding"),
        Reason(1206, DetectionResult.DETECTION_ATTEST_ANOMALY,
            "The boot properties claim a locked device while the attested " +
                "root of trust disagrees"),

        Reason(905, DetectionResult.DETECTION_ROOT_HIDER,
            "A tmpfs is mounted from a source named after a root solution"),

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
     * Every flag some code in this table can put a line under. A flag missing
     * from this set can still be set by a run, and would render as a red row
     * with nothing beneath it to read.
     */
    val flagsWithText: Set<Int> get() = BY_CODE.values.mapTo(HashSet()) { it.flag }

    /** Which flag a code explains, or null if this build has no text for it. */
    fun flagOf(code: Int): Int? = BY_CODE[code]?.flag

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
