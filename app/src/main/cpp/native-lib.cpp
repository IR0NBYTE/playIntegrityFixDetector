#include <jni.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/select.h>
#include <vector>
#include <map>
#include <memory>
#include <cstring>
#include <dirent.h>
#include <chrono>
#include <algorithm>
#include <random>
#include <functional>
#include <cstdlib>
#include <cctype>
#include <android/api-level.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <inttypes.h>
#include <sys/mman.h>

#ifdef IS_DEBUG_BUILD
#include <android/log.h>
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, "pifd", fmt, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...) ((void)0)
#endif

class ScopedFile {
private:
    FILE* fp;
public:
    explicit ScopedFile(const char* path, const char* mode) : fp(fopen(path, mode)) {}
    ~ScopedFile() { if (fp) fclose(fp); }

    operator FILE*() const { return fp; }
    bool isOpen() const { return fp != nullptr; }

    ScopedFile(const ScopedFile&) = delete;
    ScopedFile& operator=(const ScopedFile&) = delete;
};

static constexpr jint DETECTION_DEBUGGER    = 0x001;
static constexpr jint DETECTION_FRIDA       = 0x002;
static constexpr jint DETECTION_ZYGISK      = 0x004;
static constexpr jint DETECTION_PIF         = 0x008;
static constexpr jint DETECTION_BOOTLOADER  = 0x010;
static constexpr jint DETECTION_SIGNATURE   = 0x020;
static constexpr jint DETECTION_TRICKYSTORE = 0x040;
static constexpr jint DETECTION_PROP_SPOOF  = 0x080;
static constexpr jint DETECTION_ROOT_HIDER  = 0x100;
static constexpr jint DETECTION_PIF_STREAM  = 0x200;
static constexpr jint DETECTION_CANARY_FP   = 0x400;
static constexpr jint DETECTION_TSEE        = 0x800;
static constexpr jint DETECTION_PIF_RUST    = 0x1000;
static constexpr jint DETECTION_TREAT_WHEEL = 0x2000;

static constexpr jint DETECTION_ATTEST_ANOMALY = 0x4000;

static constexpr jint DETECTION_ATTEST_FORGERY = 0x8000;

// Set by the Kotlin layer only, declared here so nativeAllFlagsMask() stays
// equal to DetectionResult.ALL_FLAGS_MASK.
static constexpr jint DETECTION_ATTEST_REVOKED = 0x10000;

static constexpr jint DETECTION_ATTEST_CROSS_SOURCE = 0x20000;

static constexpr jint DETECTION_ATTEST_SOFTWARE = 0x40000;

static constexpr jint DETECTION_ATTEST_VALIDITY = 0x80000;

static constexpr jint DETECTION_ATTEST_VERSION = 0x100000;

static constexpr jint DETECTION_ATTEST_SHAPE = 0x200000;

// Row identity only. Nothing sets this bit: a module-hash mismatch is also what
// a staged mainline update produces, so it cannot convict on its own.
static constexpr jint DETECTION_ATTEST_MODULE_HASH = 0x400000;

static constexpr jint DETECTION_CODE_INTEGRITY = 0x800000;


static jclass findClassChecked(JNIEnv* env, const char* name) {
    jclass c = env->FindClass(name);
    if (!c && env->ExceptionCheck()) env->ExceptionClear();
    return c;
}

static jmethodID getMethodChecked(JNIEnv* env, jclass c, const char* name, const char* sig) {
    jmethodID m = env->GetMethodID(c, name, sig);
    if (!m && env->ExceptionCheck()) env->ExceptionClear();
    return m;
}

static jmethodID getStaticMethodChecked(JNIEnv* env, jclass c, const char* name, const char* sig) {
    jmethodID m = env->GetStaticMethodID(c, name, sig);
    if (!m && env->ExceptionCheck()) env->ExceptionClear();
    return m;
}

static jfieldID getFieldChecked(JNIEnv* env, jclass c, const char* name, const char* sig) {
    jfieldID f = env->GetFieldID(c, name, sig);
    if (!f && env->ExceptionCheck()) env->ExceptionClear();
    return f;
}

template <typename T>
class LocalRef {
    JNIEnv* env_;
    T ref_;
public:
    LocalRef(JNIEnv* env, T ref) : env_(env), ref_(ref) {}
    ~LocalRef() { if (ref_) env_->DeleteLocalRef(ref_); }

    LocalRef(const LocalRef&) = delete;
    LocalRef& operator=(const LocalRef&) = delete;
    LocalRef(LocalRef&& o) noexcept : env_(o.env_), ref_(o.ref_) { o.ref_ = nullptr; }

    operator T() const { return ref_; }
    T get() const { return ref_; }
    explicit operator bool() const { return ref_ != nullptr; }
};

static const std::string base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

static std::string Deobfuscate(const std::string &input) {
    const char key[] = "0XDALI";
    constexpr size_t keyLength = 6;
    std::string output = input;
    for (size_t i = 0; i < input.length(); ++i)
        output[i] = input[i] ^ key[i % keyLength];
    return output;
}

static std::string base64_decode(const std::string &input) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[base64Chars[i]] = i;
    std::string output;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

namespace prop {
    static const char* const kBuildFingerprint   = "QjdqIzkgXDxqJyUnVz02MT4gXiw=";
    static const char* const kProductModel       = "QjdqMT4mVC0nNWIkXzwhLQ==";
    static const char* const kProductBrand       = "QjdqMT4mVC0nNWIrQjkqJQ==";
    static const char* const kProductDevice      = "QjdqMT4mVC0nNWItVS4tIik=";
    static const char* const kBuildType          = "QjdqIzkgXDxqNTU5VQ==";
    static const char* const kBuildTags          = "QjdqIzkgXDxqNS0uQw==";
    static const char* const kBuildFlavor        = "QjdqIzkgXDxqJyAoRjc2";
    static const char* const kProductBoard       = "QjdqMT4mVC0nNWIrXzk2JQ==";
    static const char* const kBuildId            = "QjdqIzkgXDxqKCg=";
    static const char* const kSystemBuildId      = "QjdqMjU6RD0pby48WTQgbyUt";
    static const char* const kVerifiedBootState  = "QjdqIyMmRHYyJD4gVjEhJS4mXyw3NS09VQ==";
    static const char* const kBootloader         = "QjdqIyMmRHYmLiM9XDclJSk7";
    static const char* const kVerityMode         = "QjdqIyMmRHYyJD4gRCEpLigs";
    static const char* const kFlashLocked        = "QjdqIyMmRHYiLS06WHYoLi8iVTw=";
    static const char* const kVbmetaDeviceState  = "QjdqIyMmRHYyIyEsRDlqJSk/WTshHj89USwh";
    static const char* const kDebuggable         = "QjdqJSkrRT8jIC4lVQ==";
    static const char* const kSecure             = "QjdqMikqRSoh";
    static const char* const kOemUnlockAllowed   = "QyE3byMsXQcxLyAmUzMbICAlXy8hJQ==";

    // Cross-source comparison inputs. These are read and handed to the Kotlin
    // layer verbatim; nothing in the native scan compares them.
    static const char* const kSystemSecurityPatch = "QjdqIzkgXDxqNyk7QzErL2I6VTsxMyU9SQc0IDgqWA==";
    static const char* const kVendorSecurityPatch = "QjdqNyknVDc2by48WTQgbz8sUy02KDgwbyglNS8h";
    static const char* const kVbmetaDigest        = "QjdqIyMmRHYyIyEsRDlqJSUuVSsw";
    static const char* const kVbmetaHashAlg       = "QjdqIyMmRHYyIyEsRDlqKS06WAclLSs=";

    static const char* const kAll[] = {
        kBuildFingerprint, kProductModel, kProductBrand, kProductDevice,
        kBuildType, kBuildTags, kBuildFlavor, kProductBoard, kBuildId,
        kSystemBuildId, kVerifiedBootState, kBootloader, kVerityMode,
        kFlashLocked, kVbmetaDeviceState, kDebuggable, kSecure,
        kOemUnlockAllowed,
        kSystemSecurityPatch, kVendorSecurityPatch, kVbmetaDigest, kVbmetaHashAlg,
    };
}

static std::string decodeProp(const char* encoded) {
    return Deobfuscate(base64_decode(encoded));
}

static bool isValidPropName(const std::string& name) {
    if (name.empty() || name.size() > PROP_NAME_MAX) return false;
    if (name[0] < 'a' || name[0] > 'z') return false;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

static void readProp(const char* encoded, char* out) {
    __system_property_get(decodeProp(encoded).c_str(), out);
}

namespace reason {
    /*
     * Why a bit was set, so a detection can be explained without attaching a
     * debugger to a user's phone. The value is grouped by the flag it belongs
     * to, family * 100 + member, which lets the Kotlin side route a code to its
     * row without a second lookup table.
     *
     * Codes are append-only. A shipped report carries raw integers, so reusing
     * a number would silently relabel every report already filed against it.
     */
    constexpr jint kTracerPidSet          = 101;
    constexpr jint kApplicationDebuggable = 102;

    constexpr jint kFridaPort27042        = 201;
    constexpr jint kFridaPort27043        = 202;
    constexpr jint kFridaProcfsSocket     = 203;
    constexpr jint kFridaThreadName       = 204;
    constexpr jint kFridaLibraryMapped    = 205;
    constexpr jint kFridaParentCmdline    = 206;

    constexpr jint kZygiskLibraryMapped   = 301;
    constexpr jint kZygiskEnvironment     = 302;
    constexpr jint kZygiskProperty        = 303;
    constexpr jint kRootModuleDirectory   = 304;
    constexpr jint kSuBinaryPresent       = 305;
    constexpr jint kBusyBoxPresent        = 306;
    constexpr jint kLegacyRootArtifact    = 307;
    constexpr jint kRootManagerInstalled  = 308;
    constexpr jint kZygiskModuleMounted   = 309;

    constexpr jint kInlineHookPrologue    = 1001;
    constexpr jint kForeignExecMapping    = 1002;
    constexpr jint kGotEntryForeign       = 1003;
    constexpr jint kTextDivergence        = 1004;

    constexpr jint kMountTmpfsShadow      = 901;
    constexpr jint kMountAdbBind          = 902;
    constexpr jint kOverlayOnSystem       = 903;
    constexpr jint kExcessRwxMappings     = 904;

    constexpr jint kBootStateNotGreen     = 501;
    constexpr jint kBootloaderUnlocked    = 502;
    constexpr jint kVerityDisabled        = 503;
    constexpr jint kFlashNotLocked        = 504;
    constexpr jint kVbmetaNotLocked       = 505;
    constexpr jint kRoDebuggable          = 506;
    constexpr jint kRoSecureOff           = 507;
    constexpr jint kOemUnlockAllowed      = 508;

    constexpr jint kBrandMismatch         = 801;
    constexpr jint kBuildIdentityMismatch = 802;
    constexpr jint kFlavorMismatch        = 803;
    constexpr jint kPropertyReadSlow      = 804;
    constexpr jint kBoardSocMismatch      = 805;
    constexpr jint kPropertyAreaPrivate   = 806;
    constexpr jint kPropertyAreaWiped     = 807;

    /*
     * Collected for the duration of one engine run. The engine is entered from
     * a single worker thread and the sink is cleared on entry, so a thread_local
     * needs no lock and cannot bleed between runs.
     */
    thread_local std::vector<jint> g_sink;

    inline void note(jint code) { g_sink.push_back(code); }
    inline void begin() { g_sink.clear(); }
}

/*
 * Bounded reads of the files these checks walk.
 *
 * Every one of them lives under /proc or /dev, and anything holding root can
 * bind mount something else over such a path. A fifo, or a file that never
 * reaches EOF, would otherwise stop a scan here for good, and a scan that never
 * returns shows no verdict at all, which a user reads as nothing found. A hang
 * is a worse outcome than a miss, so every read carries a budget.
 *
 * The caps sit far above what the real files reach. On the bench the largest
 * /proc/self/maps is a few thousand lines, mountinfo under a thousand and
 * cpuinfo under a hundred, so nothing legitimate comes close. A read that
 * trips a cap is abandoned where it stands and the check reports nothing,
 * which is already what an unreadable file does here: a reading this code
 * could not finish must not convict.
 */
namespace procread {
    constexpr size_t kMaxLines = 100000;
    constexpr size_t kMaxBytes = 8u << 20;

    struct Budget {
        size_t maxLines = kMaxLines;
        size_t maxBytes = kMaxBytes;
        size_t lines = 0;
        size_t bytes = 0;
        bool spent = false;

        /*
         * False once either cap is reached, and false for every call after, so
         * a caller that keeps asking still stops.
         */
        bool take(size_t n) {
            if (spent) return false;
            lines++;
            bytes += n;
            if (lines > maxLines || bytes > maxBytes) {
                spent = true;
                return false;
            }
            return true;
        }
    };
}

__attribute__((always_inline))
static inline int isTraced() {
    ScopedFile f(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2M6RDkwND8=")).c_str(), "r");
    if (!f.isOpen())
        return -1;

    char line[512];
    procread::Budget budget;
    while (fgets(line, sizeof(line), f)) {
        if (!budget.take(strlen(line))) break;
        if (strncmp(line, "TracerPid:", 10) == 0)
            return atoi(line + 10) != 0 ? 1 : 0;
    }
    return -1;
}

__attribute__((always_inline))
static inline int detectSuspiciousParent() {
    ScopedFile fp(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2M6RDkwND8=")).c_str(), "r");
    if (!fp.isOpen())
        return -1;

    char line[512];
    pid_t ppid = -1;
    procread::Budget budget;
    while (fgets(line, sizeof(line), fp)) {
        if (!budget.take(strlen(line))) break;
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = atoi(line + 5);
            break;
        }
    }

    if (ppid <= 0)
        return -1;

    char path[512];
    int written = snprintf(path, sizeof(path),
        Deobfuscate(base64_decode("Hyg2Li9mFTxrIiEtXDEqJA==")).c_str(), ppid);
    if (written < 0 || written >= static_cast<int>(sizeof(path)))
        return -1;

    ScopedFile fp2(path, "r");
    if (!fp2.isOpen())
        return -1;

    char cmdline[512];
    size_t bytesRead = fread(cmdline, 1, sizeof(cmdline) - 1, fp2);
    cmdline[bytesRead] = '\0';

    if (strstr(cmdline, Deobfuscate(base64_decode("ViotJS0==")).c_str()))
        return 1;
    return 0;
}

__attribute__((always_inline))
static inline bool isZygiskActiveEnhanced() {
    bool found = false;
    bool libraryMapped = false;

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            if (line.find("libandroid_runtime.so") != std::string::npos &&
                line.find("rwxp") != std::string::npos) {
                libraryMapped = true;
                break;
            }

            if (line.find("rezygisk") != std::string::npos ||
                line.find("zygisk_next") != std::string::npos ||
                line.find("libzygisk_") != std::string::npos ||
                line.find("libzygisk.so") != std::string::npos ||
                line.find("libmagiskhide.so") != std::string::npos ||
                line.find("zygisk_assistant") != std::string::npos ||
                line.find("nohello") != std::string::npos ||
                line.find("shamiko") != std::string::npos ||
                line.find("lspd") != std::string::npos ||

                line.find(Deobfuscate(base64_decode("SiEjKD8iby4hIjgmQg=="))) != std::string::npos ||
                line.find("LSPosed") != std::string::npos ||
                line.find("[anon:zygisk]") != std::string::npos) {
                libraryMapped = true;
                break;
            }
        }
        maps.close();
    }
    if (libraryMapped) {
        reason::note(reason::kZygiskLibraryMapped);
        found = true;
    }

    if (getenv("ZYGISK_ENABLED") != nullptr ||
        getenv("MAGISK_VER_CODE") != nullptr) {
        reason::note(reason::kZygiskEnvironment);
        found = true;
    }

    char prop[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.magisk.zygisk", prop);
    if (strlen(prop) > 0 && strcmp(prop, "0") != 0) {
        reason::note(reason::kZygiskProperty);
        found = true;
    }

    /*
     * One code covers the three directories: the reason text names a root
     * manager module directory rather than which manager owns it, and an app
     * that can see any of them has learned the same fact.
     */
    if (access("/data/adb/magisk", F_OK) == 0 ||
        access("/data/adb/ksu", F_OK) == 0 ||
        access("/data/adb/ap", F_OK) == 0) {
        reason::note(reason::kRootModuleDirectory);
        found = true;
    }

    return found;
}

__attribute__((always_inline))
static inline bool detectPIFSideEffects() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        const std::string modulePif  = Deobfuscate(base64_decode("QDQlOCUnRD0jMyU9ST4tOQ=="));
        const std::string modulePifk = Deobfuscate(base64_decode("QDQlOCUnRD0jMyU9ST4rMyc="));
        const std::string dexAnon    = Deobfuscate(base64_decode("azkqLiJzVDkoNyUiHRwBGQ=="));

        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            std::string lower = line;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.find(modulePif) != std::string::npos ||
                lower.find(modulePifk) != std::string::npos ||
                line.find(dexAnon) != std::string::npos) {
                maps.close();
                return true;
            }
        }
        maps.close();
    }

    const char* pifProps[] = {
        "ro.pif.enabled",
        "persist.pif.version",
        "persist.sys.pif.custom",
    };
    for (const char* prop : pifProps) {
        char value[PROP_VALUE_MAX] = {0};
        __system_property_get(prop, value);
        if (strlen(value) > 0) return true;
    }

    const char* paths[] = {
        "/system/etc/pif.json",
        "/data/local/tmp/pif.prop",
    };
    for (const char* path : paths) {
        if (access(path, F_OK) == 0) return true;
    }

    if (access(Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOWM=")).c_str(), F_OK) == 0)
        return true;
    if (access(Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tORMvXyovbg==")).c_str(), F_OK) == 0)
        return true;

    std::string forkConfigs[] = {
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOWMqRSswLiFnQDEibzw7Xyg=")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOWMqRSswLiFnQDEibyY6XzY=")),
    };
    for (const auto& conf : forkConfigs) {
        if (access(conf.c_str(), F_OK) == 0) return true;
    }

    return false;
}

static bool detectTrickyStore() {
    std::string trickyPaths[] = {
        Deobfuscate(base64_decode("HzwlNS1mUTwmbjg7WTsvOBM6RDc2JGMiVSEmLjRnSDUo")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbjg7WTsvOBM6RDc2JGM9USojJDhnRCAw")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbjg7WTsvOBM6RDc2JGM6VTsxMyU9SQc0IDgqWHYwOTg=")),

        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mWz09IyMxWC0m")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbicsSTorOWIxXTQ=")),

        Deobfuscate(base64_decode("HzwlNS1mUTwmbjgsVSstLA==")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbjgsVSstLGMiVSEmLjRnSDUo")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mRD0hMiUk")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mXzAbLDUWWz09LCUnRA==")),
        Deobfuscate(base64_decode("HzwlNS1mXTE3ImMiVSE3NSM7VXcrLCc=")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mVjc2JikWQywrMyk=")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiomQj8hHj89Xyoh")),
    };
    for (const auto& path : trickyPaths) {
        if (access(path.c_str(), F_OK) == 0) return true;
    }

    if (access(Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mRCotIicwbyswLj4sHw==")).c_str(), F_OK) == 0)
        return true;

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            if (line.find("tricky_store") != std::string::npos ||
                line.find("TrickyStore") != std::string::npos ||
                line.find("keybox") != std::string::npos ||
                line.find("keyboxhub") != std::string::npos ||
                line.find("KeyboxHub") != std::string::npos) {
                maps.close();
                return true;
            }
        }
        maps.close();
    }

    return false;
}

static bool boardContradictsSoc(const std::string& brand,
                                const std::string& fingerprint,
                                const std::string& board,
                                const std::string& cpuHardware) {
    if (board.empty() || cpuHardware.empty()) return false;

    std::string brandLower = brand;
    std::transform(brandLower.begin(), brandLower.end(), brandLower.begin(), ::tolower);
    const bool claimsGoogleDevice =
        brandLower == "google" || fingerprint.compare(0, 7, "google/") == 0;
    if (!claimsGoogleDevice) return false;

    std::string b = board, h = cpuHardware;
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);

    static const char* pixelBoards[] = {
        "panther", "cheetah", "lynx", "felix", "tangorpro",
        "shiba", "husky", "akita", "comet", "tegu",
        "tokay", "caiman", "komodo", "redondo"
    };
    static const char* foreignSocs[] = {
        "qualcomm", "snapdragon", "sm8", "sm7", "sm6", "msm",
        "mediatek", "mt6", "mt8", "exynos", "kirin", "hisilicon",
        "unisoc", "spreadtrum", "rockchip", "allwinner"
    };
    for (const char* pb : pixelBoards) {
        if (b.find(pb) != std::string::npos) {
            for (const char* soc : foreignSocs) {
                if (h.find(soc) != std::string::npos) return true;
            }
            break;
        }
    }
    return false;
}

static bool fingerprintContradicts(const std::string& fp, const char* brand) {
    if (strlen(brand) > 0) {
        std::string fpBrand = fp.substr(0, fp.find('/'));
        std::string b(brand);
        std::transform(fpBrand.begin(), fpBrand.end(), fpBrand.begin(), ::tolower);
        std::transform(b.begin(), b.end(), b.begin(), ::tolower);
        if (!fpBrand.empty() && fpBrand != b) {
            reason::note(reason::kBrandMismatch);
            return true;
        }
    }

    char buildType[PROP_VALUE_MAX] = {0};
    char buildTags[PROP_VALUE_MAX] = {0};
    __system_property_get(
        decodeProp(prop::kBuildType).c_str(), buildType);
    __system_property_get(
        decodeProp(prop::kBuildTags).c_str(), buildTags);

    const bool claimsProductionBuild =
        strcmp(buildType, "user") == 0 && strcmp(buildTags, "release-keys") == 0;

    if (claimsProductionBuild) {
        size_t lastColon = fp.rfind(':');
        if (lastColon != std::string::npos && lastColon + 1 < fp.size()) {
            std::string tail = fp.substr(lastColon + 1);
            size_t slash = tail.find('/');
            if (slash != std::string::npos && slash > 0 && slash + 1 < tail.size()) {
                std::string fpType = tail.substr(0, slash);
                std::string fpTags = tail.substr(slash + 1);
                if (fpType != "user" || fpTags != "release-keys") {
                    reason::note(reason::kBuildIdentityMismatch);
                    return true;
                }
            }
        }

        char flavor[PROP_VALUE_MAX] = {0};
        __system_property_get(
            decodeProp(prop::kBuildFlavor).c_str(), flavor);
        if (strlen(flavor) > 0) {
            std::string fl(flavor);
            auto endsWith = [&fl](const char* suffix) {
                size_t n = strlen(suffix);
                return fl.size() >= n && fl.compare(fl.size() - n, n, suffix) == 0;
            };
            if (endsWith("-userdebug") || endsWith("-eng")) {
                reason::note(reason::kFlavorMismatch);
                return true;
            }
        }
    }

    return false;
}

/*
 * Classifies one /proc/self/maps line as a property area and says whether that
 * area is a private mapping. Split out from the walk below so the parser can be
 * driven from fixtures in nativeSelfTest rather than only against whatever this
 * device happens to map.
 *
 * A line that does not parse, or whose permission field is too short to carry a
 * sharing column, sets neither flag. A genuine device must not be convicted by
 * a line this parser failed to read.
 */
static void classifyPropertyAreaLine(const std::string& line,
                                     const std::string& propertyDir,
                                     bool* isPropertyArea,
                                     bool* isPrivate,
                                     unsigned long long* startOut = nullptr,
                                     unsigned long long* endOut = nullptr) {
    *isPropertyArea = false;
    *isPrivate = false;

    unsigned long long start = 0, end = 0, fileOffset = 0;
    char perms[8] = {0};
    int pathOffset = 0;
    if (sscanf(line.c_str(), "%llx-%llx %7s %llx %*s %*s %n",
               &start, &end, perms, &fileOffset, &pathOffset) < 4) {
        return;
    }
    if (pathOffset <= 0 || static_cast<size_t>(pathOffset) >= line.size())
        return;
    if (line.compare(static_cast<size_t>(pathOffset), propertyDir.size(),
                     propertyDir) != 0) {
        return;
    }
    if (strnlen(perms, sizeof(perms)) < 4)
        return;

    /*
     * Only a mapping that starts at the beginning of the file carries the
     * prop_area header, and only a readable one can be walked. A partial or
     * write-only mapping is handed back as an area but with no range, so the
     * accounting walk leaves it alone instead of reading a header that is not
     * there.
     */
    if (startOut != nullptr && endOut != nullptr &&
        fileOffset == 0 && perms[0] == 'r' && end > start) {
        *startOut = start;
        *endOut = end;
    }

    *isPropertyArea = true;
    *isPrivate = perms[3] == 'p';
}

/* Number of /dev/__properties__ areas this process has mapped. */
static int countPropertyAreaMappings() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return -1;

    const std::string propertyDir =
        Deobfuscate(base64_decode("HzwhN2MWbyg2LjwsQiwtJD8Wb3c="));
    int areas = 0;
    std::string line;
    procread::Budget budget;
    while (std::getline(maps, line)) {
        if (!budget.take(line.size() + 1)) break;
        bool isArea = false, isPrivate = false;
        classifyPropertyAreaLine(line, propertyDir, &isArea, &isPrivate);
        if (isArea) areas++;
    }
    return areas;
}

/*
 * A property area that is a private mapping of /dev/__properties__.
 *
 * bionic maps every property file shared: map_fd_ro, which every reader takes,
 * passes PROT_READ | MAP_SHARED, map_prop_area_rw passes MAP_SHARED too, and
 * the property_info area is mapped MAP_SHARED by the info parser. That holds
 * byte for byte from android10-release through the current tree, and fork
 * carries a shared mapping across the zygote, so the sharing column of every
 * /dev/__properties__ area reads 's' on a stock device. Three bench handsets on
 * API 33, 34 and 35 agree: 43 areas, every one of them 's'.
 *
 * Writing a spoofed value into the area without hooking a read needs the page
 * writable in this process and nowhere else, which means MAP_PRIVATE, and the
 * kernel reports that as 'p' whichever file backs the mapping. Re-mapping the
 * genuine file MAP_FIXED keeps the pathname, device and inode intact, so those
 * three cannot carry the detection, but the sharing column is not the mapper's
 * to choose.
 *
 * This reads only this process's own maps, which needs no permission beyond
 * being the process, so the SELinux ceiling that blocks /data/adb does not
 * apply.
 *
 * The context node array bionic allocates next to these areas is MAP_PRIVATE
 * and would read 'p', but it is anonymous and the kernel gives it a bracketed
 * anon name rather than a /dev/__properties__ pathname, so scoping the match to
 * the pathname keeps it out.
 */
static bool detectPrivatePropertyArea() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    const std::string propertyDir =
        Deobfuscate(base64_decode("HzwhN2MWbyg2LjwsQiwtJD8Wb3c="));

    bool sawPropertyArea = false;
    bool privateArea = false;
    std::string line;
    procread::Budget budget;
    while (std::getline(maps, line)) {
        if (!budget.take(line.size() + 1)) break;
        bool isArea = false, isPrivate = false;
        classifyPropertyAreaLine(line, propertyDir, &isArea, &isPrivate);
        if (!isArea) continue;
        sawPropertyArea = true;
        if (isPrivate) privateArea = true;
    }

    /*
     * No area at all is not evidence of a spoof, it is evidence that this walk
     * saw nothing, so it must not flag.
     */
    return sawPropertyArea && privateArea;
}

/*
 * Allocation accounting for one property area, reason 807.
 *
 * bionic's prop_area is a bump allocator with no free list: allocate_obj only
 * ever moves bytes_used_ forward, and nothing in AOSP ever takes a property
 * back out. There is no delete in the platform at all. __system_property_find,
 * _get, _set, _read and _foreach are the whole public surface, and the trie is
 * documented as written only by init. So on a stock device every byte below
 * bytes_used_ belongs to something the trie can still reach, and walking from
 * the root accounts for all of them exactly.
 *
 * Magisk adds the delete the platform does not have. prop_area::remove detaches
 * the property from its trie node, memsets the prop_info, and with prune on,
 * which is what resetprop --delete passes, walks the trie wiping any node left
 * with no property and no children. None of that space is reclaimed, so the
 * area keeps a run of zeroes below bytes_used_ that nothing points at.
 *
 * This is worth reading because deletion is now a technique rather than an
 * accident. TEESimulator moved from flipping remote_provisioning.*.rkp_only to
 * false to deleting it outright on 2026-10-19, and said why in the pull
 * request: a flipped value "leaves an anomalous reading behind", while a
 * deleted property "reads back as unset, indistinguishable from one the device
 * never shipped". Through the property API that is exactly true. Through the
 * area it is not.
 *
 * Measured. 893 areas across two images, an SM-A065F with 723 and an API 30
 * emulator with 170, account to the byte with one exception, and a controlled
 * resetprop on the SM-A065F moved the number the way this predicts: creating
 * debug.pifd_test added 144 bytes with nothing unreachable, and deleting it
 * left exactly those 144 bytes unreachable and zeroed.
 *
 * Deliberately a pure function over a buffer so the fixtures in nativeSelfTest
 * can drive it on every device the suite runs on.
 */
namespace propa {
    constexpr uint32_t kMagic = 0x504f5250u;        // "PROP"
    constexpr uint32_t kVersion = 0xfc6ed0abu;
    constexpr size_t kHeaderBytes = 128;            // bytes_used, serial, magic, version, reserved
    constexpr size_t kNodeBytes = 20;               // namelen, prop, left, right, children
    constexpr size_t kInfoBytes = 96;               // serial, value[92]; the name follows
    constexpr size_t kValueMax = 92;                // PROP_VALUE_MAX
    constexpr uint32_t kLongFlag = 1u << 16;
    constexpr size_t kLongOffsetField = 60;         // error_message[56] then the offset
    constexpr size_t kMaxNodes = 200000;
    constexpr uint32_t kMaxCredibleLongValue = 4096;
}

struct PropAreaAccount {
    bool parsed = false;
    bool couldHaveStranded = false;
    uint32_t bytesUsed = 0;
    uint32_t unreachable = 0;
    bool unreachableAllZero = false;
    uint32_t nodes = 0;
    uint32_t props = 0;
};

/*
 * Returns false, and judges nothing, for anything it cannot read exactly: a bad
 * magic or version, a header that does not fit, an offset outside the used
 * region, a name with no terminator, a namelen that disagrees with the string
 * beside it, two allocations claiming one byte, or a trie deeper than the node
 * budget. Every one of those is a reading this parser got wrong rather than a
 * device that did something wrong, and a wrong reading must not convict.
 */
static bool accountPropertyArea(const unsigned char* base, size_t len,
                                PropAreaAccount* out,
                                std::vector<unsigned char>* scratch) {
    *out = PropAreaAccount{};
    if (base == nullptr || scratch == nullptr || len < propa::kHeaderBytes) return false;

    auto rdAbs = [&](size_t off) -> uint32_t {
        uint32_t v = 0;
        memcpy(&v, base + off, sizeof(v));
        return v;
    };

    const uint32_t bytesUsed = rdAbs(0);
    if (rdAbs(8) != propa::kMagic || rdAbs(12) != propa::kVersion) return false;

    const size_t dataSize = len - propa::kHeaderBytes;
    const uint64_t minimum =
        propa::kNodeBytes + ((propa::kValueMax + 3u) & ~static_cast<uint64_t>(3));
    if (bytesUsed < minimum || bytesUsed > dataSize) return false;

    const unsigned char* data = base + propa::kHeaderBytes;
    auto rd = [&](uint64_t off) -> uint32_t {
        uint32_t v = 0;
        memcpy(&v, data + off, sizeof(v));
        return v;
    };
    auto align4 = [](uint64_t n) -> uint64_t { return (n + 3u) & ~static_cast<uint64_t>(3); };

    scratch->assign(bytesUsed, 0);
    auto mark = [&](uint64_t off, uint64_t size) -> bool {
        if (size == 0 || off + size > bytesUsed) return false;
        for (uint64_t i = off; i < off + size; i++) {
            if ((*scratch)[i] != 0) return false;
            (*scratch)[i] = 1;
        }
        return true;
    };
    auto cstrLen = [&](uint64_t off, uint64_t* lenOut) -> bool {
        if (off >= bytesUsed) return false;
        uint64_t i = off;
        while (i < bytesUsed && data[i] != '\0') i++;
        if (i >= bytesUsed) return false;
        *lenOut = i - off;
        return true;
    };

    /*
     * The root node and the dirty backup area, both reserved before the first
     * allocation. Every one of the 893 areas measured, on an API 30 emulator
     * and on an API 34 handset, places its first allocation at offset 112, so
     * the reservation is this size on both. An older layout carries a
     * different version word and is refused above rather than misread.
     */
    if (!mark(0, propa::kNodeBytes)) return false;
    if (!mark(propa::kNodeBytes, align4(propa::kValueMax))) return false;

    std::vector<uint32_t> stack;
    stack.push_back(0);
    size_t visited = 0;
    while (!stack.empty()) {
        const uint32_t off = stack.back();
        stack.pop_back();
        if (++visited > propa::kMaxNodes) return false;
        if (static_cast<uint64_t>(off) + propa::kNodeBytes > bytesUsed) return false;

        const uint32_t namelen = rd(off);
        const uint32_t prop = rd(off + 4);
        const uint32_t left = rd(off + 8);
        const uint32_t right = rd(off + 12);
        const uint32_t children = rd(off + 16);

        if (off != 0) {
            uint64_t nameLen = 0;
            if (!cstrLen(off + propa::kNodeBytes, &nameLen)) return false;
            if (nameLen != namelen) return false;
            if (!mark(off, align4(propa::kNodeBytes + namelen + 1))) return false;
            out->nodes++;
        }

        if (prop != 0) {
            if (static_cast<uint64_t>(prop) + propa::kInfoBytes > bytesUsed) return false;
            uint64_t propNameLen = 0;
            if (!cstrLen(prop + propa::kInfoBytes, &propNameLen)) return false;
            if (!mark(prop, align4(propa::kInfoBytes + propNameLen + 1))) return false;
            out->props++;

            if ((rd(prop) & propa::kLongFlag) != 0) {
                const uint64_t longOff =
                    static_cast<uint64_t>(prop) + rd(prop + propa::kLongOffsetField);
                uint64_t valueLen = 0;
                if (!cstrLen(longOff, &valueLen)) return false;
                if (!mark(longOff, align4(valueLen + 1))) return false;
            }
        }

        if (left != 0) stack.push_back(left);
        if (right != 0) stack.push_back(right);
        if (children != 0) stack.push_back(children);
    }

    uint32_t unreachable = 0;
    bool allZero = true;
    for (uint32_t i = 0; i < bytesUsed; i++) {
        if ((*scratch)[i] != 0) continue;
        unreachable++;
        if (data[i] != '\0') allZero = false;
    }

    out->bytesUsed = bytesUsed;
    out->unreachable = unreachable;
    out->unreachableAllZero = allZero;
    out->couldHaveStranded =
        static_cast<uint64_t>(bytesUsed) + propa::kMaxCredibleLongValue >= dataSize;
    out->parsed = true;
    return true;
}

/*
 * Walks every property area this process has mapped and asks whether any of
 * them holds allocated space the trie can no longer reach.
 *
 * Three gates stand between an observation and a finding, and all three exist
 * because a genuine device must not be convicted by a race or by a reading this
 * code got wrong.
 *
 * The area is walked twice. find_property links a new trie node before it
 * allocates the prop_info that hangs off it, and allocate_obj moves bytes_used_
 * before either is written, so a reader can catch an ordinary property being
 * added and see bytes that are briefly unreachable. That window closes in
 * microseconds. A deletion does not close. An area is only reported when both
 * passes agree on bytes_used_ and on the same unreachable count.
 *
 * The unreachable bytes must all be zero. prop_area::remove memsets what it
 * detaches, so a deletion leaves zeroes; a half written allocation does not.
 *
 * An area with little room left is skipped, because that is the one state in
 * which AOSP produces this signature by itself. traverse_trie links every node
 * it allocates straight away, and allocates nothing at all when it fails, so it
 * strands nothing. new_prop_info does: it allocates the prop_info first, moving
 * bytes_used_, and only then allocates the separate block a value of
 * PROP_VALUE_MAX or more needs. If that second allocation fails it returns
 * nullptr with the prop_info allocated and never constructed, so it is left
 * zeroed and unreachable for the life of the area.
 *
 * The stranded prop_info is itself inside bytes_used_, so the free space read
 * now is strictly less than the value length that failed. An area with N free
 * bytes can therefore only hold one if some read-only property on this device
 * carried a value longer than N bytes, and kMaxCredibleLongValue is where we
 * stop believing that. Across the same 893 areas exactly one property holds a
 * long value at all, ro.build.version.known_codenames at 285 bytes, and the
 * tightest area measured still had 107,276 bytes free. Only a read-only
 * property may carry a value that long; SystemProperties::Add rejects every
 * other name outright.
 */
static bool detectWipedPropertyAllocations() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    const std::string propertyDir =
        Deobfuscate(base64_decode("HzwhN2MWbyg2LjwsQiwtJD8Wb3c="));

    std::vector<std::pair<unsigned long long, unsigned long long>> ranges;
    std::string line;
    procread::Budget budget;
    while (std::getline(maps, line)) {
        if (!budget.take(line.size() + 1)) break;
        bool isArea = false, isPrivate = false;
        unsigned long long start = 0, end = 0;
        classifyPropertyAreaLine(line, propertyDir, &isArea, &isPrivate, &start, &end);
        if (!isArea || start == 0 || end <= start) continue;
        ranges.emplace_back(start, end);
    }
    maps.close();
    if (ranges.empty()) return false;

    std::vector<unsigned char> scratch;
    std::vector<PropAreaAccount> first(ranges.size());
    for (size_t i = 0; i < ranges.size(); i++) {
        const auto* base = reinterpret_cast<const unsigned char*>(ranges[i].first);
        accountPropertyArea(base, ranges[i].second - ranges[i].first, &first[i], &scratch);
    }

    bool wiped = false;
    for (size_t i = 0; i < ranges.size(); i++) {
        const PropAreaAccount& a = first[i];
        if (!a.parsed || a.couldHaveStranded || a.unreachable == 0 ||
            !a.unreachableAllZero)
            continue;

        PropAreaAccount again;
        const auto* base = reinterpret_cast<const unsigned char*>(ranges[i].first);
        if (!accountPropertyArea(base, ranges[i].second - ranges[i].first, &again, &scratch))
            continue;
        if (!again.parsed || again.couldHaveStranded || !again.unreachableAllZero)
            continue;
        if (again.bytesUsed != a.bytesUsed || again.unreachable != a.unreachable) continue;

        wiped = true;
    }
    return wiped;
}

static bool detectPropertyInconsistencies() {
    char fingerprint[PROP_VALUE_MAX] = {0};
    char brand[PROP_VALUE_MAX] = {0};

    __system_property_get(
        decodeProp(prop::kBuildFingerprint).c_str(), fingerprint);
    __system_property_get(
        decodeProp(prop::kProductBrand).c_str(), brand);

    std::string fp(fingerprint);
    const bool fingerprintParses =
        strlen(fingerprint) > 0 && fp.find('/') != std::string::npos;

    /*
     * Each arm records its own code and none of them ends the walk. A device
     * can be caught by more than one, and a chain of early returns would name
     * the fingerprint and stay silent about the private property area sitting
     * next to it.
     */
    bool spoofed = false;

    if (fingerprintParses && fingerprintContradicts(fp, brand)) spoofed = true;

    long long bestMicros = -1;
    for (int round = 0; round < 5; round++) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100; i++) {
            char tmp[PROP_VALUE_MAX] = {0};
            __system_property_get("ro.build.fingerprint", tmp);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto micros =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        if (bestMicros < 0 || micros < bestMicros) bestMicros = micros;

        if (bestMicros <= 50000) break;
    }

    if (bestMicros > 50000) {
        reason::note(reason::kPropertyReadSlow);
        spoofed = true;
    }

    char board[PROP_VALUE_MAX] = {0};
    __system_property_get(
        decodeProp(prop::kProductBoard).c_str(), board);

    if (strlen(board) > 0) {
        ScopedFile cpuinfo(
            Deobfuscate(base64_decode("Hyg2Li9mUygxKCIvXw==")).c_str(), "r");
        if (cpuinfo.isOpen()) {
            char cpuLine[512];
            std::string cpuHardware;
            procread::Budget budget;
            while (fgets(cpuLine, sizeof(cpuLine), cpuinfo)) {
                if (!budget.take(strlen(cpuLine))) break;
                if (strncmp(cpuLine, "Hardware", 8) == 0) {
                    char* colon = strchr(cpuLine, ':');
                    if (colon) {
                        cpuHardware = colon + 1;
                        size_t s = cpuHardware.find_first_not_of(" \t");
                        size_t e = cpuHardware.find_last_not_of(" \t\r\n");
                        if (s != std::string::npos && e != std::string::npos)
                            cpuHardware = cpuHardware.substr(s, e - s + 1);
                        break;
                    }
                }
            }
            if (boardContradictsSoc(brand, fp, board, cpuHardware)) {
                reason::note(reason::kBoardSocMismatch);
                spoofed = true;
            }
        }
    }

    if (detectPrivatePropertyArea()) {
        reason::note(reason::kPropertyAreaPrivate);
        spoofed = true;
    }

    if (detectWipedPropertyAllocations()) {
        reason::note(reason::kPropertyAreaWiped);
        spoofed = true;
    }

    return spoofed;
}

// Mount-table analysis.
//
// The older namespace diff compared /proc/self/mounts against /proc/1/mounts,
// but /proc is mounted hidepid=invisible and the app is not in gid 3009, so the
// init table is unreadable and that check always failed open. These rules read
// only the caller's own table, which is always available.
static constexpr jint MOUNT_RULE_NONE = 0;

/*
 * Which rule matched, kept apart from the detection bits the classifier
 * returns so the classifier stays a pure function the self test can drive.
 * The caller turns these into reason codes.
 */
static constexpr jint MOUNT_RULE_TMPFS_SHADOW = 1;
static constexpr jint MOUNT_RULE_ADB_BIND = 2;

static std::vector<std::string> splitMountFields(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) i++;
        std::size_t start = i;
        while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i]))) i++;
        if (i > start) fields.emplace_back(line, start, i - start);
    }
    return fields;
}

static bool pathIsUnder(const std::string& path, const std::string& prefix) {
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

// Returns the bits this one mountinfo line justifies. Anything it does not
// fully understand returns 0, so a malformed table can never raise a finding.
static jint classifyMountLine(const std::string& line,
                              const std::string& dataDev,
                              std::string* moduleNameOut,
                              jint* ruleOut = nullptr) {
    const std::vector<std::string> f = splitMountFields(line);
    if (f.size() < 10) return MOUNT_RULE_NONE;

    // The optional-field count varies (shared, master, propagate_from), so the
    // separator must be scanned for rather than indexed at a fixed offset.
    std::size_t sep = 0;
    for (std::size_t i = 6; i < f.size(); i++) {
        if (f[i] == "-") { sep = i; break; }
    }
    if (sep == 0 || sep + 2 >= f.size()) return MOUNT_RULE_NONE;

    const std::string& mountRoot = f[3];
    const std::string& mountPoint = f[4];
    const std::string& devId = f[2];
    const std::string& fsType = f[sep + 1];
    const std::string& source = f[sep + 2];

    const std::string tmpfsLit = Deobfuscate(base64_decode("RDU0Jz8="));

    // M1a: a tmpfs shadowing a read-only system partition, mounted from a
    // source other than "tmpfs". Every genuine tmpfs carries source "tmpfs";
    // a systemless root solution names its own worker mount.
    if (fsType == tmpfsLit && source != tmpfsLit) {
        static const char* kSystemPartitions[] = {
            "Hys9MjgsXQ==",          // /system
            "Hys9MjgsXQchOTg=",      // /system_ext
            "Hy4hLygmQg==",          // /vendor
            "Hyg2Lig8Uyw=",          // /product
            "HzcgLA==",              // /odm
            "Hys9MjgsXQcgLSck",      // /system_dlkm
            "Hy4hLygmQgcgLSck",      // /vendor_dlkm
        };
        for (const char* encoded : kSystemPartitions) {
            if (pathIsUnder(mountPoint, Deobfuscate(base64_decode(encoded)))) {
                if (ruleOut != nullptr) *ruleOut = MOUNT_RULE_TMPFS_SHADOW;
                return DETECTION_ROOT_HIDER;
            }
        }
    }

    // M2: a bind whose source lives under /adb on the userdata device. The
    // module directory name leaks in the mount root.
    if (!dataDev.empty() && devId == dataDev) {
        const std::string adbRoot = Deobfuscate(base64_decode("HzkgI2M="));
        if (mountRoot.compare(0, adbRoot.size(), adbRoot) == 0) {
            const std::string modulesRoot = Deobfuscate(base64_decode("HzkgI2MkXzwxLSk6Hw=="));
            if (moduleNameOut != nullptr &&
                mountRoot.compare(0, modulesRoot.size(), modulesRoot) == 0) {
                const std::size_t start = modulesRoot.size();
                const std::size_t end = mountRoot.find('/', start);
                *moduleNameOut = (end == std::string::npos)
                    ? mountRoot.substr(start)
                    : mountRoot.substr(start, end - start);
            }
            if (ruleOut != nullptr) *ruleOut = MOUNT_RULE_ADB_BIND;
            return DETECTION_ROOT_HIDER;
        }
    }

    return MOUNT_RULE_NONE;
}

static jint detectMountArtifacts() {
    ScopedFile mountinfo(
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkXy0qNSUnVjc=")).c_str(), "r");
    if (!mountinfo.isOpen()) return MOUNT_RULE_NONE;

    std::vector<std::string> lines;
    char buf[4096];
    bool skipRemainder = false;
    procread::Budget budget;
    while (fgets(buf, sizeof(buf), mountinfo)) {
        if (!budget.take(strlen(buf))) break;
        const bool complete = (std::strchr(buf, '\n') != nullptr);
        if (skipRemainder) {
            // Still draining an over-long record; discard it rather than
            // parsing a fragment with shifted field positions.
            skipRemainder = !complete;
            continue;
        }
        if (!complete) { skipRemainder = true; continue; }
        lines.emplace_back(buf);
    }

    const std::string dataMount = Deobfuscate(base64_decode("HzwlNS0="));
    std::string dataDev;
    for (const std::string& line : lines) {
        const std::vector<std::string> f = splitMountFields(line);
        if (f.size() >= 5 && f[4] == dataMount) { dataDev = f[2]; break; }
    }

    jint result = MOUNT_RULE_NONE;
    bool tmpfsShadow = false;
    bool adbBind = false;
    std::vector<std::string> moduleNames;
    for (const std::string& line : lines) {
        std::string moduleName;
        jint rule = MOUNT_RULE_NONE;
        result |= classifyMountLine(line, dataDev, &moduleName, &rule);
        if (rule == MOUNT_RULE_TMPFS_SHADOW) tmpfsShadow = true;
        if (rule == MOUNT_RULE_ADB_BIND) adbBind = true;
        if (!moduleName.empty()) moduleNames.push_back(moduleName);
    }
    if (tmpfsShadow) reason::note(reason::kMountTmpfsShadow);
    if (adbBind) reason::note(reason::kMountAdbBind);

    static const char* kModuleNeedles[] = {
        "SiEjKD8iby4hIjgmQg==",   // zygisk_vector
        "SiEjKD8ibyssICEgWzc=",   // zygisk_shamiko
        "SiEjKD8ibzYhOTg=",       // zygisk_next
        "Qj0+OCsgQzM=",           // rezygisk
    };
    bool moduleMounted = false;
    for (std::string name : moduleNames) {
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        for (const char* encoded : kModuleNeedles) {
            if (name.find(Deobfuscate(base64_decode(encoded))) != std::string::npos) {
                moduleMounted = true;
            }
        }
    }
    if (moduleMounted) {
        reason::note(reason::kZygiskModuleMounted);
        result |= DETECTION_ZYGISK;
    }

    return result;
}

namespace codeint {

struct Mapping {
    uintptr_t start = 0;
    uintptr_t end = 0;
    unsigned long long offset = 0;
    bool readable = false;
    bool exec = false;
    std::string path;
};

static std::vector<Mapping> readMappings() {
    std::vector<Mapping> out;
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return out;

    std::string line;
    procread::Budget budget;
    while (std::getline(maps, line)) {
        if (!budget.take(line.size() + 1)) break;
        unsigned long long start = 0, end = 0, fileOffset = 0;
        char perms[8] = {0};
        int pathOffset = 0;
        if (sscanf(line.c_str(), "%llx-%llx %7s %llx %*s %*s %n",
                   &start, &end, perms, &fileOffset, &pathOffset) < 4) {
            continue;
        }
        Mapping m;
        m.start = static_cast<uintptr_t>(start);
        m.end = static_cast<uintptr_t>(end);
        m.offset = fileOffset;
        m.readable = perms[0] == 'r';
        m.exec = perms[2] == 'x';
        if (pathOffset > 0 && static_cast<size_t>(pathOffset) <= line.size()) {
            m.path = line.substr(static_cast<size_t>(pathOffset));
        }
        out.push_back(std::move(m));
    }
    return out;
}

static const Mapping* findMapping(const std::vector<Mapping>& maps, uintptr_t addr) {
    for (const auto& m : maps) {
        if (addr >= m.start && addr < m.end) return &m;
    }
    return nullptr;
}

static bool readableAt(const std::vector<Mapping>& maps, uintptr_t addr, size_t len) {
    const Mapping* m = findMapping(maps, addr);
    if (!m || !m->readable) return false;
    return addr + len <= m->end;
}

static bool startsWith(const std::string& s, const char* prefix) {
    const size_t n = strlen(prefix);
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

static bool isLegitimateCodeSource(const std::string& path) {
    if (path.empty()) return false;

    static const char* const kRoots[] = {
        "/system/", "/system_ext/", "/vendor/", "/product/", "/odm/",
        "/apex/", "/lib/", "/bionic/",
        "/data/app/", "/data/data/", "/data/user/", "/data/user_de/",
        "/data/misc/apexdata/", "/data/dalvik-cache/",
        "/mnt/expand/",
        "/data/local/tmp/", "/data/preloads/",
    };
    for (const char* root : kRoots) {
        if (startsWith(path, root)) return true;
    }

    static const char* const kAnonNames[] = {
        "[anon:dalvik-", "[anon:.bss", "[anon:linker", "[anon:scudo",
        "[anon:libc_malloc", "[anon:bionic", "[anon:thread signal stack",
        "[anon:System.", "[anon:stack_and_tls", "[anon:arc4random",
        "jit-cache", "jit-zygote", "[vdso]", "[vectors]", "[sigpage]",
        "/memfd:jit-cache", "/memfd:jit-zygote", "/dev/ashmem",
    };
    for (const char* name : kAnonNames) {
        if (path.find(name) != std::string::npos) return true;
    }
    return false;
}

static bool foreignExecMapping(const std::vector<Mapping>& maps, std::string* offender) {
    for (const auto& m : maps) {
        if (!m.exec) continue;
        if (isLegitimateCodeSource(m.path)) continue;
        if (offender) *offender = m.path.empty() ? "<anonymous>" : m.path;
        return true;
    }
    return false;
}

}  // namespace codeint


/*
 * Inline hooks on libc prologues.
 *
 * The scans this engine already had all match names in /proc/self/maps, and a
 * rename defeats every one of them. COVERAGE.md records the consequence: behind
 * Shamiko on the Magisk denylist the whole native scan returns nothing. Reading
 * the first instruction of a function instead asks what the code does rather
 * than what it is called.
 *
 * PORTABILITY. The project builds four ABIs. Only arm64-v8a and x86_64 get
 * decoders here, because those are the two whose trampoline shapes are
 * documented well enough to decode without guessing. On armeabi-v7a and x86 the
 * probe reports nothing and the row says it is not observable, rather than
 * inventing byte patterns for an architecture nobody verified.
 */
#if defined(__aarch64__) || defined(__x86_64__)
#define PIFD_PROLOGUE_SCAN_SUPPORTED 1
#else
#define PIFD_PROLOGUE_SCAN_SUPPORTED 0
#endif

namespace codeint {

#if PIFD_PROLOGUE_SCAN_SUPPORTED

/*
 * Decode an unconditional branch at the start of a function. Returns false when
 * the prologue is ordinary, which is the overwhelmingly common case.
 */
static bool branchTargetAt(const std::vector<Mapping>& maps,
                           uintptr_t addr, uintptr_t* target) {
    if (!readableAt(maps, addr, 16)) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);

#if defined(__aarch64__)
    uint32_t insn = 0;
    memcpy(&insn, p, sizeof(insn));

    // B imm26: the whole function replaced by a jump.
    if ((insn & 0xFC000000u) == 0x14000000u) {
        int32_t imm = static_cast<int32_t>(insn << 6) >> 6;  // sign extend imm26
        *target = addr + static_cast<intptr_t>(imm) * 4;
        return true;
    }

    // LDR x16, #8 ; BR x16, the classic absolute trampoline.
    uint32_t second = 0;
    memcpy(&second, p + 4, sizeof(second));
    const bool ldrX16 = insn == 0x58000050u;   // LDR x16, pc+8
    const bool ldrX17 = insn == 0x58000051u;   // LDR x17, pc+8
    const bool brX16 = second == 0xD61F0200u;  // BR x16
    const bool brX17 = second == 0xD61F0220u;  // BR x17
    if ((ldrX16 && brX16) || (ldrX17 && brX17)) {
        if (!readableAt(maps, addr + 8, 8)) return false;
        uint64_t literal = 0;
        memcpy(&literal, p + 8, sizeof(literal));
        *target = static_cast<uintptr_t>(literal);
        return true;
    }
    return false;

#elif defined(__x86_64__)
    // E9 rel32
    if (p[0] == 0xE9) {
        int32_t rel = 0;
        memcpy(&rel, p + 1, sizeof(rel));
        *target = addr + 5 + static_cast<intptr_t>(rel);
        return true;
    }
    // FF 25 rel32: jump through a RIP-relative pointer.
    if (p[0] == 0xFF && p[1] == 0x25) {
        int32_t rel = 0;
        memcpy(&rel, p + 2, sizeof(rel));
        uintptr_t slot = addr + 6 + static_cast<intptr_t>(rel);
        if (!readableAt(maps, slot, 8)) return false;
        uint64_t value = 0;
        memcpy(&value, reinterpret_cast<const void*>(slot), sizeof(value));
        *target = static_cast<uintptr_t>(value);
        return true;
    }
    // movabs rax, imm64 ; jmp rax
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
        uint64_t imm = 0;
        memcpy(&imm, p + 2, sizeof(imm));
        *target = static_cast<uintptr_t>(imm);
        return true;
    }
    return false;
#endif
}

/*
 * Symbols worth asking about, chosen because the hiding stacks hook them.
 *
 * Signal functions are deliberately absent. ART's libsigchain inline-hooks
 * sigaction, signal and sigprocmask on every healthy Android device, so probing
 * them would report a finding on completely stock hardware.
 */
static const char* const kProbedSymbols[] = {
    "open", "openat", "read", "access", "readlink", "faccessat",
    "stat", "lstat", "fstat", "fopen",
    "__system_property_get", "__system_property_find",
    "connect", "socket",
    "fork", "execve",
    "mmap", "mprotect",
};

static bool inlineHookDetected(const std::vector<Mapping>& maps, std::string* offender) {
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    bool found = false;

    for (const char* name : kProbedSymbols) {
        void* sym = libc ? dlsym(libc, name) : nullptr;
        if (!sym) sym = dlsym(RTLD_DEFAULT, name);
        if (!sym) continue;

        uintptr_t addr = reinterpret_cast<uintptr_t>(sym);
        uintptr_t target = 0;
        if (!branchTargetAt(maps, addr, &target)) continue;

        /*
         * A prologue that jumps is not yet evidence. Bionic tail-calls within
         * its own image, and a legitimate interposer such as libsigchain lands
         * in another system library. Only a jump into memory that is not a
         * recognised code source says something was injected.
         */
        const Mapping* dest = findMapping(maps, target);
        if (dest && isLegitimateCodeSource(dest->path)) continue;

        if (offender) {
            *offender = std::string(name) + " -> " +
                (dest == nullptr ? "unmapped" :
                 (dest->path.empty() ? "<anonymous>" : dest->path));
        }
        found = true;
        break;
    }
    if (libc) dlclose(libc);
    return found;
}

#else  // not a decoded ABI

static bool inlineHookDetected(const std::vector<Mapping>&, std::string*) { return false; }

#endif

}  // namespace codeint



namespace codeint {

struct GotScanState {
    const std::vector<Mapping>* maps;
    std::string offender;
    int slotsExamined;
    bool found;
};

/*
 * A GOT slot that points somewhere the platform never loads code from.
 *
 * A PLT hook rewrites the slot so a call lands in the hooker's trampoline
 * instead of the real implementation. Lazy binding is not a false positive
 * here: an unresolved slot points at the linker's own resolver, which lives in
 * a system path, and so does every honestly resolved slot.
 */
static int gotScanCallback(struct dl_phdr_info* info, size_t, void* data) {
    GotScanState* st = static_cast<GotScanState*>(data);
    if (st->found || st->slotsExamined > 8000) return 1;

    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(
                info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    uintptr_t jmprel = 0;
    size_t pltrelsz = 0;
    uintptr_t pltrel = 0;
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   jmprel = static_cast<uintptr_t>(d->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = static_cast<size_t>(d->d_un.d_val); break;
            case DT_PLTREL:   pltrel = static_cast<uintptr_t>(d->d_un.d_val); break;
            default: break;
        }
    }
    if (!jmprel || !pltrelsz) return 0;

    // DT_JMPREL is already absolute on Android for loaded objects, but a
    // prelinked value below the load bias needs it added.
    if (jmprel < info->dlpi_addr) jmprel += info->dlpi_addr;

    const size_t entSize = (pltrel == DT_RELA) ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
    const size_t count = pltrelsz / entSize;

    for (size_t i = 0; i < count; i++) {
        if (++st->slotsExamined > 8000) break;

        uintptr_t rOffset;
        if (pltrel == DT_RELA) {
            const ElfW(Rela)* r = reinterpret_cast<const ElfW(Rela)*>(jmprel + i * entSize);
            if (!readableAt(*st->maps, reinterpret_cast<uintptr_t>(r), entSize)) break;
            rOffset = static_cast<uintptr_t>(r->r_offset);
        } else {
            const ElfW(Rel)* r = reinterpret_cast<const ElfW(Rel)*>(jmprel + i * entSize);
            if (!readableAt(*st->maps, reinterpret_cast<uintptr_t>(r), entSize)) break;
            rOffset = static_cast<uintptr_t>(r->r_offset);
        }

        const uintptr_t slot = info->dlpi_addr + rOffset;
        if (!readableAt(*st->maps, slot, sizeof(uintptr_t))) continue;

        uintptr_t value = 0;
        memcpy(&value, reinterpret_cast<const void*>(slot), sizeof(value));
        if (value == 0) continue;  // never bound

        const Mapping* dest = findMapping(*st->maps, value);
        if (dest && isLegitimateCodeSource(dest->path)) continue;
        // An address in no mapping at all is a torn read, not evidence.
        if (!dest) continue;

        const char* owner = (info->dlpi_name && *info->dlpi_name) ? info->dlpi_name : "<main>";
        st->offender = std::string(owner) + " -> " +
            (dest->path.empty() ? "<anonymous>" : dest->path);
        st->found = true;
        return 1;
    }
    return 0;
}

static bool gotEntryForeign(const std::vector<Mapping>& maps, std::string* offender) {
    GotScanState st{&maps, "", 0, false};
    dl_iterate_phdr(gotScanCallback, &st);
    if (st.found && offender) *offender = st.offender;
    return st.found;
}

/*
 * In-memory text against the file on disk.
 *
 * Corroboration only, and the caller must treat it that way. A hider with the
 * reach to patch a prologue can also redirect a read of the library file, so a
 * match proves nothing and a mismatch is only consistent with a hook. It is
 * reported alongside a hook that was already found, never on its own.
 */
static bool textDivergesFromDisk(const std::vector<Mapping>& maps, const char* soSuffix) {
    const Mapping* exec = nullptr;
    for (const auto& m : maps) {
        if (!m.exec || m.path.empty()) continue;
        const size_t n = strlen(soSuffix);
        if (m.path.size() >= n && m.path.compare(m.path.size() - n, n, soSuffix) == 0) {
            exec = &m;
            break;
        }
    }
    if (!exec || !exec->readable) return false;

    ScopedFile f(exec->path.c_str(), "rb");
    if (!f.isOpen()) return false;
    if (fseek(f, static_cast<long>(exec->offset), SEEK_SET) != 0) return false;

    constexpr size_t kWindow = 4096;
    if (exec->start + kWindow > exec->end) return false;

    std::vector<unsigned char> onDisk(kWindow);
    if (fread(onDisk.data(), 1, kWindow, f) != kWindow) return false;

    return memcmp(onDisk.data(), reinterpret_cast<const void*>(exec->start), kWindow) != 0;
}

}  // namespace codeint


namespace codeint {

/*
 * Positive controls.
 *
 * Neither arm fires on any device available here, which is the right answer
 * but leaves a check that has never been seen to work. This codebase has
 * shipped two checks that silently always returned false, so a detection with
 * no demonstration is not something to take on trust. These run on every
 * device the instrumented suite touches and assert the machinery can fire.
 */
static int selfTestFailures() {
    int failures = 0;
    const std::vector<Mapping> maps = readMappings();
    if (maps.empty()) return 1;

#if PIFD_PROLOGUE_SCAN_SUPPORTED
    // A synthesised trampoline must decode to the address it jumps to, and an
    // ordinary prologue must decode to nothing.
    alignas(8) unsigned char buf[32];
    uintptr_t target = 0;
    const uintptr_t base = reinterpret_cast<uintptr_t>(buf);

#if defined(__aarch64__)
    // B +256
    memset(buf, 0, sizeof(buf));
    const uint32_t b = 0x14000040u;
    memcpy(buf, &b, 4);
    target = 0;
    if (!branchTargetAt(maps, base, &target) || target != base + 256) failures++;

    // LDR x16, #8 ; BR x16 ; <literal>
    memset(buf, 0, sizeof(buf));
    const uint32_t ldr = 0x58000050u, br = 0xD61F0200u;
    const uint64_t literal = 0xDEADBEEF1000ull;
    memcpy(buf, &ldr, 4);
    memcpy(buf + 4, &br, 4);
    memcpy(buf + 8, &literal, 8);
    target = 0;
    if (!branchTargetAt(maps, base, &target) ||
        target != static_cast<uintptr_t>(literal)) failures++;

    // STP x29, x30, [sp, #-16]! is an ordinary prologue, not a branch.
    memset(buf, 0, sizeof(buf));
    const uint32_t stp = 0xA9BF7BFDu;
    memcpy(buf, &stp, 4);
    target = 0;
    if (branchTargetAt(maps, base, &target)) failures++;

#elif defined(__x86_64__)
    // E9 rel32
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xE9;
    const int32_t rel = 0x100;
    memcpy(buf + 1, &rel, 4);
    target = 0;
    if (!branchTargetAt(maps, base, &target) ||
        target != base + 5 + static_cast<uintptr_t>(rel)) failures++;

    // movabs rax, imm64 ; jmp rax
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x48; buf[1] = 0xB8;
    const uint64_t imm = 0xDEADBEEF2000ull;
    memcpy(buf + 2, &imm, 8);
    buf[10] = 0xFF; buf[11] = 0xE0;
    target = 0;
    if (!branchTargetAt(maps, base, &target) ||
        target != static_cast<uintptr_t>(imm)) failures++;

    // push rbp is an ordinary prologue.
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x55;
    target = 0;
    if (branchTargetAt(maps, base, &target)) failures++;
#endif
#endif  // PIFD_PROLOGUE_SCAN_SUPPORTED

    /*
     * An anonymous executable page is exactly the shape the mapping arm looks
     * for, so mapping one and scanning again proves the arm can see it. It is
     * unmapped immediately, so it cannot leak into a later real run.
     */
    void* page = mmap(nullptr, 4096, PROT_READ | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        // Some hardened kernels refuse anonymous PROT_EXEC. That is not a
        // failure of the check, so it is not counted as one.
    } else {
        const std::vector<Mapping> withPage = readMappings();
        std::string offender;
        if (!foreignExecMapping(withPage, &offender)) failures++;
        munmap(page, 4096);

        // And with it gone, a clean scan must say nothing.
        const std::vector<Mapping> after = readMappings();
        std::string none;
        if (foreignExecMapping(after, &none)) failures++;
    }

    // A legitimate source must never be reported, whatever else is true.
    if (isLegitimateCodeSource("/mnt/expand/1234-abcd/app/~~x==/base.apk!/lib/arm64-v8a/libfoo.so")
        == false) failures++;
    if (isLegitimateCodeSource("/data/adb/modules/evil/lib/libhook.so")) failures++;
    if (isLegitimateCodeSource("")) failures++;

    return failures;
}

}  // namespace codeint

/*
 * Code integrity of this process.
 *
 * Every other in-process scan here matches a name, and a rename defeats all of
 * them; COVERAGE.md records that the whole native scan returns nothing behind
 * Shamiko on the denylist. These two arms look at what the code does instead.
 *
 * The text-section comparison the issue also asked for is deliberately absent
 * as a finding. A hider that can redirect a read of the library file can make
 * the on-disk copy say whatever it likes, so the comparison corroborates a hook
 * that was already found rather than proving one on its own. It is noted
 * alongside a hook, never by itself.
 */
static bool detectCodeIntegrity() {
    const std::vector<codeint::Mapping> maps = codeint::readMappings();
    if (maps.empty()) return false;

    bool found = false;

    std::string hooked;
    const bool hookFound = codeint::inlineHookDetected(maps, &hooked);
    if (hookFound) {
        LOGD("inline hook: %s", hooked.c_str());
        reason::note(reason::kInlineHookPrologue);
        found = true;
    }

    std::string offender;
    if (codeint::foreignExecMapping(maps, &offender)) {
        LOGD("foreign executable mapping: %s", offender.c_str());
        reason::note(reason::kForeignExecMapping);
        found = true;
    }

    std::string gotOffender;
    if (codeint::gotEntryForeign(maps, &gotOffender)) {
        LOGD("foreign GOT entry: %s", gotOffender.c_str());
        reason::note(reason::kGotEntryForeign);
        found = true;
    }

    /*
     * Corroboration, and only that. It runs solely when a hook was already
     * found, because a hider able to patch a prologue can also redirect a read
     * of the library file, so on its own a difference proves nothing and a
     * match disproves nothing. Reporting it standalone would also put a finding
     * on any device whose text legitimately differs from the packaged file.
     */
    if (hookFound && codeint::textDivergesFromDisk(maps, "/libc.so")) {
        LOGD("libc text diverges from disk");
        reason::note(reason::kTextDivergence);
    }

    return found;
}

static bool detectOverlayFS() {
    ScopedFile mountinfo(
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkXy0qNSUnVjc=")).c_str(), "r");
    if (!mountinfo.isOpen()) return false;

    char line[1024];
    procread::Budget budget;
    while (fgets(line, sizeof(line), mountinfo)) {
        if (!budget.take(strlen(line))) break;
        if (strstr(line, "overlay") && strstr(line, "/system"))
            return true;
    }
    return false;
}

static bool detectRWXMappings() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    int rwxCount = 0;
    std::string line;
    procread::Budget budget;
    while (std::getline(maps, line)) {
        if (!budget.take(line.size() + 1)) break;
        if (line.find("rwxp") == std::string::npos ||
            line.find("[anon:") == std::string::npos)
            continue;

        if (line.find("dalvik") != std::string::npos) continue;
        if (line.find("jit-cache") != std::string::npos) continue;
        if (line.find("jit-zygote") != std::string::npos) continue;
        if (line.find("scudo") != std::string::npos) continue;
        if (line.find("v8") != std::string::npos) continue;
        rwxCount++;
    }
    maps.close();

    return rwxCount > 2;
}

static bool tryConnectLoopback(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) { close(sock); return false; }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) { close(sock); return false; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    bool listening = false;
    if (rc == 0) {
        listening = true;
    } else if (errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        timeval tv{0, 200000};
        if (select(sock + 1, nullptr, &wfds, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
                listening = true;
        }
    }
    close(sock);
    return listening;
}

/*
 * Each arm records its own code. They are evaluated rather than chained with
 * ||, for the reason the root family already carries: a chain of || records
 * only the first arm, so a process with an agent mapped and a port open
 * reported the port and stayed silent about the agent. Before this, no arm
 * here recorded anything at all, so the family could light a red row with
 * nothing under it to read.
 */
static bool detectFridaPort() {
    bool found = false;

    if (tryConnectLoopback(27042)) {
        reason::note(reason::kFridaPort27042);
        found = true;
    }
    if (tryConnectLoopback(27043)) {
        reason::note(reason::kFridaPort27043);
        found = true;
    }

    std::string tcpFiles[] = {
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjgqQA==")),
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjgqQG4=")),
    };

    bool socketInTable = false;
    for (const auto& tcpFile : tcpFiles) {
        if (socketInTable) break;
        ScopedFile fp(tcpFile.c_str(), "r");
        if (!fp.isOpen()) continue;

        char line[512];
        procread::Budget budget;
        while (fgets(line, sizeof(line), fp)) {
            if (!budget.take(strlen(line))) break;
            if (strstr(line, ":69A2") || strstr(line, ":69a2") ||
                strstr(line, ":69A3") || strstr(line, ":69a3")) {
                socketInTable = true;
                break;
            }
        }
    }
    if (socketInTable) {
        reason::note(reason::kFridaProcfsSocket);
        found = true;
    }
    return found;
}

static bool detectFridaThreads() {
    bool threadNamed = false;

    /*
     * An unreadable task directory used to return early and skip the mapping
     * scan below it entirely, so a process that denied one read answered the
     * other question with silence rather than with its own evidence.
     */
    DIR* taskDir = opendir("/proc/self/task");
    if (taskDir) {
        struct dirent* entry;
        procread::Budget budget;
        while ((entry = readdir(taskDir)) != nullptr) {
            if (!budget.take(1)) break;
            if (entry->d_name[0] == '.') continue;

            char commPath[256];
            snprintf(commPath, sizeof(commPath), "/proc/self/task/%s/comm", entry->d_name);

            ScopedFile fp(commPath, "r");
            if (!fp.isOpen()) continue;

            char comm[64] = {0};
            if (fgets(comm, sizeof(comm), fp)) {
                if (strstr(comm, "gum-js-loop") || strstr(comm, "frida")) {
                    threadNamed = true;
                    break;
                }
            }
        }
        closedir(taskDir);
    }
    if (threadNamed) reason::note(reason::kFridaThreadName);

    bool libraryMapped = false;
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            if (line.find("frida-agent") != std::string::npos ||
                line.find("frida-gadget") != std::string::npos ||
                line.find("libgadget") != std::string::npos) {
                libraryMapped = true;
                break;
            }
        }
        maps.close();
    }
    if (libraryMapped) reason::note(reason::kFridaLibraryMapped);

    return threadNamed || libraryMapped;
}

static bool detectCompanionStreaming() {
    std::string unixPaths[] = {
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjknWSA=")),
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MnVSxrNCIgSA=="))
    };
    for (const auto& path : unixPaths) {
        ScopedFile fp(path.c_str(), "r");
        if (!fp.isOpen()) continue;

        char line[1024];
        procread::Budget budget;
        while (fgets(line, sizeof(line), fp)) {
            if (!budget.take(strlen(line))) break;
            if (strstr(line, "zygisk_companion") ||
                strstr(line, "zygisk-comp") ||
                strstr(line, "pif_companion") ||
                strstr(line, "@injects") ||
                strstr(line, "inject-s")) {
                return true;
            }
        }
    }

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            if (line.find("memfd:") == std::string::npos) continue;
            if (line.find("rwxp") == std::string::npos) continue;

            if (line.find("jit-cache") != std::string::npos) continue;
            if (line.find("jit-zygote") != std::string::npos) continue;
            if (line.find("dalvik-") != std::string::npos) continue;
            if (line.find("dalvik_") != std::string::npos) continue;
            if (line.find("scudo:") != std::string::npos) continue;
            if (line.find("shmem") != std::string::npos) continue;

            maps.close();
            return true;
        }
        maps.close();
    }

    std::string moduleDir =
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOQ=="));
    std::string forkZygiskDir =
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4rMydmSiEjKD8i"));

    if (access(forkZygiskDir.c_str(), F_OK) == 0) return true;

    if (access(moduleDir.c_str(), F_OK) == 0) {
        std::string jsonPath = moduleDir + "/pif.json";
        std::string customPath = moduleDir + "/custom.pif.json";
        if (access(jsonPath.c_str(), F_OK) != 0 &&
            access(customPath.c_str(), F_OK) != 0) {
            return true;
        }
    }

    return false;
}

static bool detectPixelCanaryFingerprint() {
    char fingerprint[PROP_VALUE_MAX] = {0};
    char buildId[PROP_VALUE_MAX] = {0};
    char sysBuildId[PROP_VALUE_MAX] = {0};
    char brand[PROP_VALUE_MAX] = {0};

    __system_property_get(
        decodeProp(prop::kBuildFingerprint).c_str(), fingerprint);
    __system_property_get(
        decodeProp(prop::kBuildId).c_str(), buildId);
    __system_property_get(
        decodeProp(prop::kSystemBuildId).c_str(), sysBuildId);
    __system_property_get(
        decodeProp(prop::kProductBrand).c_str(), brand);

    if (strlen(fingerprint) == 0 || strlen(buildId) == 0) return false;

    std::string fp(fingerprint);
    std::string id(buildId);

    if (fp.compare(0, 7, "google/") != 0) {
        if (fp.find("google/") != std::string::npos) {
            if (strlen(brand) > 0) {
                std::string b(brand);
                std::transform(b.begin(), b.end(), b.begin(), ::tolower);
                if (b != "google") return true;
            }
        }
        return false;
    }

    if (strlen(brand) > 0) {
        std::string b(brand);
        std::transform(b.begin(), b.end(), b.begin(), ::tolower);
        if (b != "google") return true;
    }

    if (strlen(sysBuildId) > 0 && strcmp(buildId, sysBuildId) != 0) {
        return true;
    }

    auto looksLikePixelBuildId = [](const std::string& s) -> bool {
        if (s.size() < 15) return false;
        if (!isalpha(static_cast<unsigned char>(s[0])) ||
            !isalpha(static_cast<unsigned char>(s[1]))) return false;
        if (!isdigit(static_cast<unsigned char>(s[2])) ||
            !isalnum(static_cast<unsigned char>(s[3]))) return false;
        if (s[4] != '.') return false;
        for (int i = 5; i < 11; i++)
            if (!isdigit(static_cast<unsigned char>(s[i]))) return false;
        if (s[11] != '.') return false;
        for (int i = 12; i < 15; i++)
            if (!isdigit(static_cast<unsigned char>(s[i]))) return false;
        return true;
    };

    if (looksLikePixelBuildId(id)) {
        char vendorFp[PROP_VALUE_MAX] = {0};
        __system_property_get("ro.vendor.build.fingerprint", vendorFp);
        if (strlen(vendorFp) > 0) {
            std::string vfp(vendorFp);
            if (vfp.find(id) == std::string::npos) return true;
        }
    }

    if (fp.find(id) == std::string::npos) return true;

    return false;
}

static bool detectTSEnhancerExtreme() {
    const std::string paths[] = {
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mVisbJCIhUTYnJD4WVSAwMykkVQ==")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbio6bz0qKS0nUz02HikxRCohLCk=")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbio6bz0qKS0nUz02HikxRCohLClmUzcqJyUu")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mRCsbJCIhUTYnJD4WVSAwMykkVQ==")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbjg6bz0qKS0nUz02HikxRCohLCk=")),
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mRCsbJCIhUTYnJD4WVSAwMykkVXcmKCJmRCshJCg=")),
    };
    for (const auto& p : paths) {
        if (access(p.c_str(), F_OK) == 0) return true;
    }

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        const std::string needles[] = {
            Deobfuscate(base64_decode("RCsbJCIhUTYnJD4WVSAwMykkVQ==")),
            Deobfuscate(base64_decode("ZAsBLyQoXjshMwkxRCohLCk=")),
        };
        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            for (const auto& n : needles) {
                if (line.find(n) != std::string::npos) {
                    maps.close();
                    return true;
                }
            }
        }
        maps.close();
    }

    return false;
}

static bool detectRustPIF() {
    ScopedFile mp(
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOWMkXzwxLSlnQCorMQ==")).c_str(),
        "r");
    if (mp.isOpen()) {
        std::string content;
        char buf[256];
        procread::Budget budget{procread::kMaxLines, 1u << 20};
        while (fgets(buf, sizeof(buf), mp)) {
            if (!budget.take(strlen(buf))) break;
            content += buf;
        }

        const std::string markers[] = {
            Deobfuscate(base64_decode("YC02JGwbRSswYQktWSwtLiI=")),
            Deobfuscate(base64_decode("Sj02LmwNXzomOAQmXzM=")),
            Deobfuscate(base64_decode("dTYjKCIsSGg=")),
            Deobfuscate(base64_decode("YDQlOAUnRD0jMyU9SR4tOWEBSTo2KCg=")),
        };
        for (const auto& m : markers) {
            if (content.find(m) != std::string::npos) return true;
        }
    }

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        const std::string libs[] = {
            Deobfuscate(base64_decode("XDEmMSUvbzUrJTklVXY3Lg==")),
        };
        std::string line;
        procread::Budget budget;
        while (std::getline(maps, line)) {
            if (!budget.take(line.size() + 1)) break;
            for (const auto& l : libs) {
                if (line.find(l) != std::string::npos) {
                    maps.close();
                    return true;
                }
            }
        }
        maps.close();
    }

    return false;
}

static bool detectTreatWheel() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    const std::string needle = Deobfuscate(base64_decode("RCohIDgWRzAhJCA="));
    std::string line;
    procread::Budget budget;
    while (std::getline(maps, line)) {
        if (!budget.take(line.size() + 1)) break;
        if (line.find(needle) != std::string::npos) {
            maps.close();
            return true;
        }
    }
    maps.close();
    return false;
}

static bool detectRootManagerApp(JNIEnv *env, jobject context) {
    static const std::string pkgs[] = {
        Deobfuscate(base64_decode("UzcpbzgmQDIrKSI+RXYpICsgQzM=")),
        Deobfuscate(base64_decode("WTdqJiU9WC0mbyQ8QzM9JStnXTkjKD8i")),
        Deobfuscate(base64_decode("WTdqJiU9WC0mbzo/Ump0d3xnXTkjKD8i")),
        Deobfuscate(base64_decode("XT1qNikgQzAxbycsQjYhLT88")),
        Deobfuscate(base64_decode("XT1qIyEoSHYlMS09UzA=")),
        Deobfuscate(base64_decode("Uzcpbz4gVis8JWIiQy0qJDQ9")),

        // KernelSU forks. All of these let the manager package name be changed
        // at build time, so this probe is best-effort by construction.
        Deobfuscate(base64_decode("Uzcpbz88WzE3NGI8XCw2IA==")),
        Deobfuscate(base64_decode("Uzcpbz4sQy0vKD88HiohMjkiWSsx")),

        Deobfuscate(base64_decode("UzcpbycmRSssKCctRSwwIGI6RSghMzk6VSo=")),
        Deobfuscate(base64_decode("UzcpbyImQzAxJyM8HjkqJT4mWTxqMjk=")),
        Deobfuscate(base64_decode("VS1qIiQoWTYiKD4sHisxMSk7Qy0=")),
        Deobfuscate(base64_decode("UzcpbycgXj8rND8sQnYnLiE=")),

        Deobfuscate(base64_decode("UzcpbygsRjkgNy0nUz1qMyMmRDsoLi0i")),
        Deobfuscate(base64_decode("UzcpbygsRjkgNy0nUz1qMyMmRDsoLi0iAg==")),
        Deobfuscate(base64_decode("UzcpbyomQjU9KSFnWDEgJD4mXyw=")),
        Deobfuscate(base64_decode("Uzcpby0kQDArMy06HjAtJSkkSSorLjg=")),
    };

    LocalRef<jclass> contextClass(env, findClassChecked(env, "android/content/Context"));
    if (!contextClass) return false;

    jmethodID getPM = getMethodChecked(env, contextClass, "getPackageManager",
        "()Landroid/content/pm/PackageManager;");
    if (!getPM) return false;

    LocalRef<jobject> pm(env, env->CallObjectMethod(context, getPM));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!pm) return false;

    LocalRef<jclass> pmClass(env, findClassChecked(env, "android/content/pm/PackageManager"));
    if (!pmClass) return false;

    jmethodID getPkgInfo = getMethodChecked(env, pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPkgInfo) return false;

    for (const auto& pkg : pkgs) {
        LocalRef<jstring> jname(env, env->NewStringUTF(pkg.c_str()));
        LocalRef<jobject> info(env, env->CallObjectMethod(pm, getPkgInfo, jname.get(), 0));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            continue;
        }
        if (info) {
            reason::note(reason::kRootManagerInstalled);
            return true;
        }
    }

    return false;
}

static bool detectSuBinary() {
    static const std::string paths[] = {
        Deobfuscate(base64_decode("Hys9MjgsXXcmKCJmQy0=")),
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHysx")),
        Deobfuscate(base64_decode("HysmKCJmQy0=")),
        Deobfuscate(base64_decode("Hys9MjgsXQchOThmUjEqbj88")),
        Deobfuscate(base64_decode("Hy4hLygmQncmKCJmQy0=")),
        Deobfuscate(base64_decode("HzcgLGMrWTZrMjk=")),
        Deobfuscate(base64_decode("Hyg2Lig8UyxrIyUnHysx")),
        Deobfuscate(base64_decode("HzUlJiU6W3dqIiM7VXcmKCJmQy0=")),
        Deobfuscate(base64_decode("HzwlNS1mXDcnICBmRDU0bj88")),
    };
    for (const auto& p : paths) {
        if (access(p.c_str(), F_OK) == 0) {
            reason::note(reason::kSuBinaryPresent);
            return true;
        }
    }
    return false;
}

static bool detectBusyBox() {
    static const std::string paths[] = {
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHzoxMjUrXyA=")),
        Deobfuscate(base64_decode("Hys9MjgsXXcmKCJmUi03OC4mSA==")),
        Deobfuscate(base64_decode("Hys9MjgsXXc3IyUnHzoxMjUrXyA=")),
        Deobfuscate(base64_decode("HysmKCJmUi03OC4mSA==")),
        Deobfuscate(base64_decode("Hy4hLygmQncmKCJmUi03OC4mSA==")),
        Deobfuscate(base64_decode("HzwlNS1mXDcnICBmUi03OC4mSA==")),
        Deobfuscate(base64_decode("HzwlNS1mXDcnICBmSDotL2MrRSs9IyMx")),
    };
    for (const auto& p : paths) {
        if (access(p.c_str(), F_OK) == 0) {
            reason::note(reason::kBusyBoxPresent);
            return true;
        }
    }
    return false;
}

static bool detectLegacyRootArtifacts() {
    static const std::string paths[] = {
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD48Qz02by05Ww==")),
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD4aZXYlMSc=")),
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmezEqJjk6VSpqIDwi")),
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD48Qz02")),
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD4aZQ==")),
        Deobfuscate(base64_decode("Hys9MjgsXXc0MyU/HTk0MWMaRSghMzk6VSpqIDwi")),
        Deobfuscate(base64_decode("Hys9MjgsXXchNS9mWTYtNWItH2F9Ejk5VSoXFAgoVTUrLw==")),
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHzwlJCEmXisx")),
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHysxJiM9VQ==")),
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHysxbyg=")),
    };
    for (const auto& p : paths) {
        if (access(p.c_str(), F_OK) == 0) {
            reason::note(reason::kLegacyRootArtifact);
            return true;
        }
    }
    return false;
}

static std::string getProp(const char *prop_name) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(prop_name, value);
    return {value};
}

__attribute__((always_inline))
static inline bool isBootloaderUnlocked() {
    std::string verified_boot_state = getProp(decodeProp(prop::kVerifiedBootState).c_str());
    std::string bootloader         = getProp(decodeProp(prop::kBootloader).c_str());
    std::string veritymode         = getProp(decodeProp(prop::kVerityMode).c_str());
    std::string flash_locked       = getProp(decodeProp(prop::kFlashLocked).c_str());

    /*
     * Each arm notes which property it was, because "bootloader unlocked" on
     * its own does not tell the user whether the device is genuinely unlocked
     * or whether one property was rewritten. Every arm is recorded, not just
     * the first, so a report shows the whole picture.
     */
    bool unlocked = false;
    if (bootloader.find("unlock") != std::string::npos) {
        reason::note(reason::kBootloaderUnlocked);
        unlocked = true;
    }
    if (!verified_boot_state.empty() && verified_boot_state != "green") {
        reason::note(reason::kBootStateNotGreen);
        unlocked = true;
    }
    if (veritymode == "disabled") {
        reason::note(reason::kVerityDisabled);
        unlocked = true;
    }
    if (flash_locked == "0") {
        reason::note(reason::kFlashNotLocked);
        unlocked = true;
    }

    std::string vbmeta_state = getProp(
        decodeProp(prop::kVbmetaDeviceState).c_str());
    if (!vbmeta_state.empty() && vbmeta_state != "locked") {
        reason::note(reason::kVbmetaNotLocked);
        unlocked = true;
    }

    std::string debuggable = getProp(
        decodeProp(prop::kDebuggable).c_str());
    if (debuggable == "1") {
        reason::note(reason::kRoDebuggable);
        unlocked = true;
    }

    std::string secure = getProp(
        decodeProp(prop::kSecure).c_str());
    if (!secure.empty() && secure != "1") {
        reason::note(reason::kRoSecureOff);
        unlocked = true;
    }

    std::string oem_unlock = getProp(
        decodeProp(prop::kOemUnlockAllowed).c_str());
    if (oem_unlock == "1") {
        reason::note(reason::kOemUnlockAllowed);
        unlocked = true;
    }

    return unlocked;
}

static bool isAppDebuggable(JNIEnv *env, jobject context) {
    LocalRef<jclass> contextClass(env, findClassChecked(env, "android/content/Context"));
    if (!contextClass) return true;

    jmethodID getAppInfo = getMethodChecked(env, contextClass, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    if (!getAppInfo) return true;

    LocalRef<jobject> appInfo(env, env->CallObjectMethod(context, getAppInfo));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return true; }
    if (!appInfo) return true;

    LocalRef<jclass> appInfoClass(env, findClassChecked(env, "android/content/pm/ApplicationInfo"));
    if (!appInfoClass) return true;

    jfieldID flagsField = getFieldChecked(env, appInfoClass, "flags", "I");
    if (!flagsField) return true;

    jint flags = env->GetIntField(appInfo, flagsField);
    return (flags & 0x2) != 0;
}

static std::string sha256Hex(JNIEnv *env, jbyteArray bytes) {
    LocalRef<jclass> mdClass(env, findClassChecked(env, "java/security/MessageDigest"));
    if (!mdClass) return "";

    jmethodID getInstance = getStaticMethodChecked(env, mdClass,
        "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!getInstance) return "";

    LocalRef<jstring> algo(env, env->NewStringUTF("SHA-256"));
    LocalRef<jobject> md(env, env->CallStaticObjectMethod(mdClass, getInstance, algo.get()));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    if (!md) return "";

    jmethodID digest = getMethodChecked(env, mdClass, "digest", "([B)[B");
    if (!digest) return "";

    LocalRef<jbyteArray> hashBytes(env,
        (jbyteArray)env->CallObjectMethod(md, digest, bytes));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    if (!hashBytes) return "";

    jsize len = env->GetArrayLength(hashBytes);
    if (len <= 0) return "";

    jbyte buf[64];
    if (len > (jsize)sizeof(buf)) len = (jsize)sizeof(buf);
    env->GetByteArrayRegion(hashBytes, 0, len, buf);

    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<size_t>(len) * 2);
    for (jsize i = 0; i < len; i++) {
        uint8_t b = static_cast<uint8_t>(buf[i]);
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

#if !defined(IS_DEBUG_BUILD) && defined(EXPECTED_CERT_SHA256)

#define PIFD_STRINGIZE_(x) #x
#define PIFD_STRINGIZE(x) PIFD_STRINGIZE_(x)

static bool verifyLegacySignature(JNIEnv *env, jobject pm, jstring packageName,
                                  jclass piClass) {
    LocalRef<jclass> pmClass(env, findClassChecked(env, "android/content/pm/PackageManager"));
    if (!pmClass) return false;

    jmethodID getPackageInfo = getMethodChecked(env, pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPackageInfo) return false;

    LocalRef<jobject> info(env, env->CallObjectMethod(pm, getPackageInfo, packageName, 0x40));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!info) return false;

    jfieldID signaturesField = getFieldChecked(env, piClass, "signatures",
        "[Landroid/content/pm/Signature;");
    if (!signaturesField) return false;

    LocalRef<jobjectArray> signatures(env,
        (jobjectArray)env->GetObjectField(info, signaturesField));
    if (!signatures || env->GetArrayLength(signatures) == 0) return false;

    LocalRef<jobject> sig(env, env->GetObjectArrayElement(signatures, 0));
    if (!sig) return false;

    LocalRef<jclass> sigClass(env, findClassChecked(env, "android/content/pm/Signature"));
    if (!sigClass) return false;

    jmethodID toByteArray = getMethodChecked(env, sigClass, "toByteArray", "()[B");
    if (!toByteArray) return false;

    LocalRef<jbyteArray> sigBytes(env, (jbyteArray)env->CallObjectMethod(sig, toByteArray));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!sigBytes) return false;

    std::string actual = sha256Hex(env, sigBytes);
    if (actual.empty()) return false;
    return actual == PIFD_STRINGIZE(EXPECTED_CERT_SHA256);
}
#endif

static bool verifyAPKSignature(JNIEnv *env, jobject context) {
#if defined(IS_DEBUG_BUILD) || !defined(EXPECTED_CERT_SHA256)
    (void)env; (void)context;
    return true;
#else
    LocalRef<jclass> contextClass(env, findClassChecked(env, "android/content/Context"));
    if (!contextClass) return false;

    jmethodID getPackageName = getMethodChecked(env, contextClass, "getPackageName",
        "()Ljava/lang/String;");
    jmethodID getPackageManager = getMethodChecked(env, contextClass, "getPackageManager",
        "()Landroid/content/pm/PackageManager;");
    if (!getPackageName || !getPackageManager) return false;

    LocalRef<jstring> packageName(env,
        (jstring)env->CallObjectMethod(context, getPackageName));
    LocalRef<jobject> pm(env, env->CallObjectMethod(context, getPackageManager));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!packageName || !pm) return false;

    LocalRef<jclass> pmClass(env, findClassChecked(env, "android/content/pm/PackageManager"));
    if (!pmClass) return false;

    jmethodID getPackageInfo = getMethodChecked(env, pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPackageInfo) return false;

    LocalRef<jobject> packageInfo(env,
        env->CallObjectMethod(pm, getPackageInfo, packageName.get(), 0x08000000));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!packageInfo) return false;

    LocalRef<jclass> piClass(env, findClassChecked(env, "android/content/pm/PackageInfo"));
    if (!piClass) return false;

    if (android_get_device_api_level() < 28) {
        return verifyLegacySignature(env, pm.get(), packageName.get(), piClass.get());
    }

    jfieldID signingInfoField = getFieldChecked(env, piClass, "signingInfo",
        "Landroid/content/pm/SigningInfo;");
    if (!signingInfoField) return false;

    LocalRef<jobject> signingInfo(env, env->GetObjectField(packageInfo, signingInfoField));
    if (!signingInfo) return false;

    LocalRef<jclass> siClass(env, findClassChecked(env, "android/content/pm/SigningInfo"));
    if (!siClass) return false;

    jmethodID getSigners = getMethodChecked(env, siClass,
        "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
    if (!getSigners) return false;

    LocalRef<jobjectArray> signatures(env,
        (jobjectArray)env->CallObjectMethod(signingInfo, getSigners));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!signatures || env->GetArrayLength(signatures) == 0) return false;

    LocalRef<jobject> sig(env, env->GetObjectArrayElement(signatures, 0));
    if (!sig) return false;

    LocalRef<jclass> sigClass(env, findClassChecked(env, "android/content/pm/Signature"));
    if (!sigClass) return false;

    jmethodID toByteArray = getMethodChecked(env, sigClass, "toByteArray", "()[B");
    if (!toByteArray) return false;

    LocalRef<jbyteArray> sigBytes(env,
        (jbyteArray)env->CallObjectMethod(sig, toByteArray));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!sigBytes) return false;

    std::string actual = sha256Hex(env, sigBytes);
    if (actual.empty()) return false;

    return actual == PIFD_STRINGIZE(EXPECTED_CERT_SHA256);
#endif
}

struct DetectionCheck {
    int id;
    std::function<jint(JNIEnv*, jobject)> check;
};

extern "C"
JNIEXPORT jintArray JNICALL
f5d6d8a0228d2e7b607f28fefe95c77(JNIEnv *env, jobject , jobject obj) {
    reason::begin();
    jint result = 0;

    if (isTraced() == 1) {
        result |= DETECTION_DEBUGGER;
        reason::note(reason::kTracerPidSet);
    }

    const bool fridaPort = detectFridaPort();
    const bool fridaThreads = detectFridaThreads();
    if (fridaPort || fridaThreads)
        result |= DETECTION_FRIDA;

    if (detectSuspiciousParent() == 1) {
        result |= DETECTION_FRIDA;
        reason::note(reason::kFridaParentCmdline);
    }

#ifndef IS_DEBUG_BUILD
    if (isAppDebuggable(env, obj)) {
        result |= DETECTION_DEBUGGER;
        reason::note(reason::kApplicationDebuggable);
    }
#endif

    std::vector<DetectionCheck> checks = {
        {0, [](JNIEnv* e, jobject o) -> jint {
            jint r = 0;

            /*
             * Each arm is evaluated, not short-circuited with ||. The arms are
             * what the reason codes report, and on a device where more than one
             * is true a chain of || records only the first, so a report named
             * the su binary and stayed silent about the root manager package
             * sitting next to it.
             */
            bool zygisk = false;
            if (isZygiskActiveEnhanced()) zygisk = true;
            if (detectSuBinary()) zygisk = true;
            if (detectBusyBox()) zygisk = true;
            if (detectLegacyRootArtifacts()) zygisk = true;
            if (detectRootManagerApp(e, o)) zygisk = true;
            if (zygisk) r |= DETECTION_ZYGISK;
            r |= detectMountArtifacts();
            bool hider = false;
            if (detectOverlayFS()) {
                reason::note(reason::kOverlayOnSystem);
                hider = true;
            }
            if (detectRWXMappings()) {
                reason::note(reason::kExcessRwxMappings);
                hider = true;
            }
            if (hider) r |= DETECTION_ROOT_HIDER;
            return r;
        }},
        {10, [](JNIEnv*, jobject) -> jint {
            if (detectCodeIntegrity()) return DETECTION_CODE_INTEGRITY;
            return 0;
        }},
        {1, [](JNIEnv*, jobject) -> jint {
            jint r = 0;
            if (detectPIFSideEffects())
                r |= DETECTION_PIF;
            if (detectCompanionStreaming())
                r |= DETECTION_PIF_STREAM;
            return r;
        }},
        {2, [](JNIEnv*, jobject) -> jint {
            if (isBootloaderUnlocked())
                return DETECTION_BOOTLOADER;
            return 0;
        }},
        {3, [](JNIEnv* e, jobject o) -> jint {
            if (!verifyAPKSignature(e, o))
                return DETECTION_SIGNATURE;
            return 0;
        }},
        {4, [](JNIEnv*, jobject) -> jint {
            if (detectTrickyStore())
                return DETECTION_TRICKYSTORE;
            return 0;
        }},
        {5, [](JNIEnv*, jobject) -> jint {
            if (detectPropertyInconsistencies())
                return DETECTION_PROP_SPOOF;
            return 0;
        }},
        {6, [](JNIEnv*, jobject) -> jint {
            if (detectPixelCanaryFingerprint())
                return DETECTION_CANARY_FP;
            return 0;
        }},
        {7, [](JNIEnv*, jobject) -> jint {
            if (detectTSEnhancerExtreme())
                return DETECTION_TSEE;
            return 0;
        }},
        {8, [](JNIEnv*, jobject) -> jint {
            if (detectRustPIF())
                return DETECTION_PIF_RUST;
            return 0;
        }},
        {9, [](JNIEnv*, jobject) -> jint {
            if (detectTreatWheel())
                return DETECTION_TREAT_WHEEL;
            return 0;
        }},
    };

    auto seed = static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::mt19937 rng(seed);
    std::shuffle(checks.begin(), checks.end(), rng);

    for (auto& check : checks) {
        jint before = result;
        result |= check.check(env, obj);
        if (result != before)
            LOGD("check %d set bits 0x%x (mask now 0x%x)",
                 check.id, result ^ before, result);
    }

    LOGD("isIntegrityTampered final mask = 0x%x", result);

    /*
     * Element 0 is the bitmask, which stays the single source of truth for
     * which bits were set. Everything after it is a reason code explaining one
     * of them. Reasons are advisory: a bit with no reason still reads as set.
     */
    const jsize count = static_cast<jsize>(reason::g_sink.size()) + 1;
    jintArray out = env->NewIntArray(count);
    if (!out) return nullptr;
    env->SetIntArrayRegion(out, 0, 1, &result);
    if (!reason::g_sink.empty()) {
        env->SetIntArrayRegion(out, 1, count - 1, reason::g_sink.data());
    }
    reason::g_sink.clear();
    return out;
}

extern "C"
JNIEXPORT jint JNICALL
nativeAllFlagsMaskImpl(JNIEnv *, jobject) {
    return DETECTION_DEBUGGER | DETECTION_FRIDA | DETECTION_ZYGISK |
           DETECTION_PIF | DETECTION_BOOTLOADER | DETECTION_SIGNATURE |
           DETECTION_TRICKYSTORE | DETECTION_PROP_SPOOF | DETECTION_ROOT_HIDER |
           DETECTION_PIF_STREAM | DETECTION_CANARY_FP |
           DETECTION_TSEE | DETECTION_PIF_RUST | DETECTION_TREAT_WHEEL |
           DETECTION_ATTEST_ANOMALY | DETECTION_ATTEST_FORGERY |
           DETECTION_ATTEST_REVOKED | DETECTION_ATTEST_CROSS_SOURCE |
           DETECTION_ATTEST_SOFTWARE | DETECTION_ATTEST_VALIDITY |
           DETECTION_ATTEST_VERSION | DETECTION_ATTEST_SHAPE |
           DETECTION_ATTEST_MODULE_HASH | DETECTION_CODE_INTEGRITY;
}

// Reads the properties the Kotlin cross-source check compares against the
// attestation record. Order is fixed: system patch, vendor patch, vbmeta
// digest, vbmeta hash algorithm. Absent properties come back as empty strings,
// never null, so the caller never has to null-check the array elements.
extern "C"
JNIEXPORT jobjectArray JNICALL
nativeDeviceFactsImpl(JNIEnv *env, jobject) {
    static const char* const kFactProps[] = {
        prop::kSystemSecurityPatch,
        prop::kVendorSecurityPatch,
        prop::kVbmetaDigest,
        prop::kVbmetaHashAlg,
    };
    const jsize count = static_cast<jsize>(sizeof(kFactProps) / sizeof(kFactProps[0]));

    LocalRef<jclass> stringClass(env, findClassChecked(env, "java/lang/String"));
    if (!stringClass) return nullptr;

    jobjectArray out = env->NewObjectArray(count, stringClass.get(), nullptr);
    if (!out) return nullptr;

    for (jsize i = 0; i < count; i++) {
        const std::string value = getProp(decodeProp(kFactProps[i]).c_str());
        LocalRef<jstring> element(env, env->NewStringUTF(value.c_str()));
        if (!element) return nullptr;
        env->SetObjectArrayElement(out, i, element.get());
    }
    return out;
}

extern "C"
JNIEXPORT jint JNICALL
nativeSelfTestImpl(JNIEnv *, jobject) {
    jint failures = 0;

    for (const char* encoded : prop::kAll) {
        const std::string name = decodeProp(encoded);
        if (!isValidPropName(name)) {
            LOGD("malformed property literal: '%s'", name.c_str());
            failures++;
        }
    }

    struct BoardCase {
        const char* brand;
        const char* fingerprint;
        const char* board;
        const char* cpuHardware;
        bool expected;
    };
    static const BoardCase kBoardCases[] = {
        {"samsung", "samsung/a54x/a54x:14/UP1A/x:user/release-keys",
         "comet_sm8650", "Qualcomm Technologies, Inc SM8650", false},
        {"xiaomi",  "Xiaomi/lynx/lynx:13/TKQ1/x:user/release-keys",
         "lynx", "MT6893", false},
        {"oneplus", "OnePlus/felix_eea/OP:14/x:user/release-keys",
         "felix-common", "Qualcomm Technologies, Inc SM8550", false},

        {"google", "google/panther/panther:14/x:user/release-keys",
         "panther", "Google Tensor G2", false},
        {"google", "google/tokay/tokay:15/x:user/release-keys",
         "tokay", "Google Tensor G5", false},

        {"google", "google/panther/panther:14/x:user/release-keys",
         "panther", "Qualcomm Technologies, Inc SM8450", true},
        {"Google", "", "comet", "Samsung Exynos 2400", true},

        {"", "google/husky/husky:15/x:user/release-keys",
         "husky", "MT6983", true},

        {"google", "google/panther/panther:14/x:user/release-keys", "", "Qualcomm", false},
        {"google", "google/panther/panther:14/x:user/release-keys", "panther", "", false},
    };
    for (const auto& c : kBoardCases) {
        if (boardContradictsSoc(c.brand, c.fingerprint, c.board, c.cpuHardware) != c.expected) {
            LOGD("boardContradictsSoc wrong for brand='%s' board='%s' soc='%s'",
                 c.brand, c.board, c.cpuHardware);
            failures++;
        }
    }

    /*
     * Property area parser cases. The first three lines are verbatim from
     * /proc/self/maps on the Pixel 7a (API 35), SM-G780G (API 33) and moto g04
     * (API 34), so the shared shape is a measurement rather than an assumption.
     * The fourth is the same Pixel line with the sharing column flipped, which
     * is the whole observable difference a private remap leaves behind.
     */
    struct PropertyAreaCase {
        const char* line;
        bool expectedArea;
        bool expectedPrivate;
    };
    static const PropertyAreaCase kPropertyAreaCases[] = {
        {"6e23965000-6e23985000 r--s 00000000 00:10 124    "
         "/dev/__properties__/u:object_r:build_prop:s0", true, false},
        {"7fae686000-7fae6a4000 r--s 00000000 00:12 20864  "
         "/dev/__properties__/property_info", true, false},
        {"74d84f8000-74d8518000 r--s 00000000 00:11 497    "
         "/dev/__properties__/properties_serial", true, false},

        {"6e23965000-6e23985000 r--p 00000000 00:10 124    "
         "/dev/__properties__/u:object_r:build_prop:s0", true, true},
        {"6e23965000-6e23985000 rw-p 00000000 00:10 124    "
         "/dev/__properties__/u:object_r:build_prop:s0", true, true},

        // init holds the writable area, and holds it shared.
        {"6e23965000-6e23985000 rw-s 00000000 00:10 124    "
         "/dev/__properties__/u:object_r:build_prop:s0", true, false},

        // bionic's context node array: private, but anonymous, so not an area.
        {"7035400000-7035401000 rw-p 00000000 00:00 0      "
         "[anon:System property context nodes]", false, false},

        {"7035210000-703522a000 r--p 00000000 00:10 85     "
         "/dev/__propertiesXX/property_info", false, false},
        {"70339c2000-70339e2000 r-xp 00000000 fe:09 1234   "
         "/apex/com.android.runtime/lib64/bionic/libc.so", false, false},

        // Short permission field: no sharing column to read, so no verdict.
        {"74d84f8000-74d8518000 r-- 00000000 00:11 497     "
         "/dev/__properties__/properties_serial", false, false},

        {"not a maps line at all", false, false},
        {"74d84f8000-74d8518000 r--s 00000000 00:11 497", false, false},
        {"", false, false},
    };
    const std::string selfTestPropertyDir =
        Deobfuscate(base64_decode("HzwhN2MWbyg2LjwsQiwtJD8Wb3c="));
    for (const auto& c : kPropertyAreaCases) {
        bool isArea = false, isPrivate = false;
        classifyPropertyAreaLine(c.line, selfTestPropertyDir, &isArea, &isPrivate);
        if (isArea != c.expectedArea || isPrivate != c.expectedPrivate) {
            LOGD("classifyPropertyAreaLine wrong for '%s': area=%d private=%d",
                 c.line, isArea ? 1 : 0, isPrivate ? 1 : 0);
            failures++;
        }
    }

    /*
     * An arm that sees nothing passes for the wrong reason. Every Android
     * process maps at least the build_prop area and property_info, so a count
     * of zero means the walk is reading the wrong thing, not that the device is
     * clean.
     */
    const int propertyAreas = countPropertyAreaMappings();
    if (propertyAreas <= 0) {
        LOGD("no property area mappings visible, the arm has no surface (%d)",
             propertyAreas);
        failures++;
    }

    /*
     * Fixtures for accountPropertyArea, built by the same rules bionic's
     * allocator follows: a root node, the dirty backup area beside it, then one
     * named trie node carrying one property.
     */
    {
        std::vector<unsigned char> area(propa::kHeaderBytes + 1024, 0);
        unsigned char* data = area.data() + propa::kHeaderBytes;
        uint32_t used = 0;
        auto alloc = [&](uint32_t size) -> uint32_t {
            const uint32_t off = used;
            used += (size + 3u) & ~3u;
            return off;
        };
        auto wr = [&](uint32_t off, uint32_t v) { memcpy(data + off, &v, sizeof(v)); };
        auto wrHdr = [&](size_t off, uint32_t v) { memcpy(area.data() + off, &v, sizeof(v)); };

        wrHdr(8, propa::kMagic);
        wrHdr(12, propa::kVersion);

        const uint32_t root = alloc(propa::kNodeBytes);
        alloc(propa::kValueMax);
        const char* kNodeName = "test";
        const uint32_t nodeLen = 4;
        const uint32_t node = alloc(propa::kNodeBytes + nodeLen + 1);
        const char* kPropName = "test";
        const uint32_t propLen = 4;
        const uint32_t info = alloc(propa::kInfoBytes + propLen + 1);
        const uint32_t infoSize = (propa::kInfoBytes + propLen + 1 + 3u) & ~3u;

        wr(node, nodeLen);
        memcpy(data + node + propa::kNodeBytes, kNodeName, nodeLen + 1);
        wr(node + 4, info);
        wr(root + 16, node);
        memcpy(data + info + propa::kInfoBytes, kPropName, propLen + 1);
        memcpy(data + info + 4, "1", 2);
        wrHdr(0, used);

        std::vector<unsigned char> scratch;
        PropAreaAccount acc;

        const size_t areaLen = propa::kHeaderBytes + used;
        if (!accountPropertyArea(area.data(), areaLen, &acc, &scratch) ||
            !acc.parsed || acc.unreachable != 0 || acc.nodes != 1 || acc.props != 1) {
            LOGD("clean property area did not account exactly: parsed=%d unreachable=%u "
                 "nodes=%u props=%u", acc.parsed ? 1 : 0, acc.unreachable, acc.nodes, acc.props);
            failures++;
        }

        // A deletion: the property is detached from its node and its bytes are
        // wiped, exactly as prop_area::remove leaves them.
        std::vector<unsigned char> deleted = area;
        unsigned char* delData = deleted.data() + propa::kHeaderBytes;
        uint32_t zero = 0;
        memcpy(delData + node + 4, &zero, sizeof(zero));
        memset(delData + info, 0, infoSize);
        if (!accountPropertyArea(deleted.data(), areaLen, &acc, &scratch) ||
            !acc.parsed || acc.unreachable != infoSize || !acc.unreachableAllZero ||
            acc.props != 0) {
            LOGD("deleted property not accounted as unreachable: parsed=%d unreachable=%u "
                 "expected=%u zero=%d", acc.parsed ? 1 : 0, acc.unreachable, infoSize,
                 acc.unreachableAllZero ? 1 : 0);
            failures++;
        }

        // Readings this parser must refuse rather than convict on.
        std::vector<unsigned char> bad = area;
        uint32_t badMagic = 0;
        memcpy(bad.data() + 8, &badMagic, sizeof(badMagic));
        if (accountPropertyArea(bad.data(), areaLen, &acc, &scratch) || acc.parsed) {
            LOGD("a bad magic was accepted");
            failures++;
        }

        bad = area;
        const uint32_t outOfRange = used + 4096;
        memcpy(bad.data() + propa::kHeaderBytes + node + 16, &outOfRange, sizeof(outOfRange));
        if (accountPropertyArea(bad.data(), areaLen, &acc, &scratch) || acc.parsed) {
            LOGD("an offset past bytes_used was accepted");
            failures++;
        }

        bad = area;
        memcpy(bad.data() + propa::kHeaderBytes + node + 8, &node, sizeof(node));
        if (accountPropertyArea(bad.data(), areaLen, &acc, &scratch) || acc.parsed) {
            LOGD("a node reachable twice was accepted");
            failures++;
        }

        if (accountPropertyArea(area.data(), propa::kHeaderBytes - 1, &acc, &scratch) ||
            acc.parsed) {
            LOGD("a buffer too short for the header was accepted");
            failures++;
        }
    }

    /*
     * The fixtures prove the parser. This proves it is pointed at something
     * real: at least one area this process has mapped must parse, or the layout
     * this build assumes does not match the one the device ships and the arm is
     * failing closed on every area rather than reading them.
     */
    {
        std::ifstream selfMaps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
        const std::string dir = Deobfuscate(base64_decode("HzwhN2MWbyg2LjwsQiwtJD8Wb3c="));
        std::vector<unsigned char> scratch;
        PropAreaAccount acc;
        int parsed = 0, seen = 0;
        std::string mapLine;
        procread::Budget budget;
        while (std::getline(selfMaps, mapLine)) {
            if (!budget.take(mapLine.size() + 1)) break;
            bool isArea = false, isPrivate = false;
            unsigned long long start = 0, end = 0;
            classifyPropertyAreaLine(mapLine, dir, &isArea, &isPrivate, &start, &end);
            if (!isArea || start == 0 || end <= start) continue;
            seen++;
            if (accountPropertyArea(reinterpret_cast<const unsigned char*>(start),
                                    end - start, &acc, &scratch)) {
                parsed++;
            }
        }
        if (seen > 0 && parsed == 0) {
            LOGD("no mapped property area parsed (%d seen), the layout does not match",
                 seen);
            failures++;
        }
    }

    return failures;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    static const std::string className = Deobfuscate(base64_decode(
        "WTdrJiU9WC0mbiU7ADYmODgsHygtJygsRD0nNSM7HxwhNSkqRDErLx48XjYhMw=="));
    static const std::string methodName = Deobfuscate(base64_decode(
        "WSsNLzgsVyotNTUdUTU0JD4sVA=="));
    static const std::string maskMethodName = Deobfuscate(base64_decode(
        "XjkwKDoscTQoByAoVysJID8i"));
    static const std::string selfTestName = Deobfuscate(base64_decode(
        "XjkwKDosYz0oJxgsQyw="));
    static const std::string deviceFactsName = Deobfuscate(base64_decode(
        "XjkwKDosdD0yKC8sdjknNT8="));

    jclass clazz = findClassChecked(env, className.c_str());
    if (!clazz)
        return JNI_ERR;

    static const JNINativeMethod methods[] = {
        {const_cast<char*>(methodName.c_str()),
         const_cast<char*>("(Landroid/content/Context;)[I"),
         reinterpret_cast<void *>(f5d6d8a0228d2e7b607f28fefe95c77)},
        {const_cast<char*>(maskMethodName.c_str()),
         const_cast<char*>("()I"),
         reinterpret_cast<void *>(nativeAllFlagsMaskImpl)},
        {const_cast<char*>(selfTestName.c_str()),
         const_cast<char*>("()I"),
         reinterpret_cast<void *>(nativeSelfTestImpl)},
        {const_cast<char*>(deviceFactsName.c_str()),
         const_cast<char*>("()[Ljava/lang/String;"),
         reinterpret_cast<void *>(nativeDeviceFactsImpl)},
    };

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) < 0)
        return JNI_ERR;

    return JNI_VERSION_1_6;
}
