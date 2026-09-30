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

__attribute__((always_inline))
static inline int isTraced() {
    ScopedFile f(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2M6RDkwND8=")).c_str(), "r");
    if (!f.isOpen())
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
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
    while (fgets(line, sizeof(line), fp)) {
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
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("libandroid_runtime.so") != std::string::npos &&
                line.find("rwxp") != std::string::npos) {
                maps.close();
                return true;
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
                maps.close();
                return true;
            }
        }
        maps.close();
    }

    if (getenv("ZYGISK_ENABLED") != nullptr ||
        getenv("MAGISK_VER_CODE") != nullptr)
        return true;

    char prop[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.magisk.zygisk", prop);
    if (strlen(prop) > 0 && strcmp(prop, "0") != 0) return true;

    if (access("/data/adb/magisk", F_OK) == 0) return true;
    if (access("/data/adb/ksu", F_OK) == 0) return true;
    if (access("/data/adb/ap", F_OK) == 0) return true;

    return false;
}

__attribute__((always_inline))
static inline bool detectPIFSideEffects() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        const std::string modulePif  = Deobfuscate(base64_decode("QDQlOCUnRD0jMyU9ST4tOQ=="));
        const std::string modulePifk = Deobfuscate(base64_decode("QDQlOCUnRD0jMyU9ST4rMyc="));
        const std::string dexAnon    = Deobfuscate(base64_decode("azkqLiJzVDkoNyUiHRwBGQ=="));

        std::string line;
        while (std::getline(maps, line)) {
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
        while (std::getline(maps, line)) {
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
        if (!fpBrand.empty() && fpBrand != b) return true;
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
                if (fpType != "user" || fpTags != "release-keys") return true;
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
            if (endsWith("-userdebug") || endsWith("-eng")) return true;
        }
    }

    return false;
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

    if (fingerprintParses && fingerprintContradicts(fp, brand)) return true;

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

    if (bestMicros > 50000) return true;

    char board[PROP_VALUE_MAX] = {0};
    __system_property_get(
        decodeProp(prop::kProductBoard).c_str(), board);

    if (strlen(board) > 0) {
        ScopedFile cpuinfo(
            Deobfuscate(base64_decode("Hyg2Li9mUygxKCIvXw==")).c_str(), "r");
        if (cpuinfo.isOpen()) {
            char cpuLine[512];
            std::string cpuHardware;
            while (fgets(cpuLine, sizeof(cpuLine), cpuinfo)) {
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
            if (boardContradictsSoc(brand, fp, board, cpuHardware)) return true;
        }
    }

    return false;
}

// Mount-table analysis.
//
// The older namespace diff compared /proc/self/mounts against /proc/1/mounts,
// but /proc is mounted hidepid=invisible and the app is not in gid 3009, so the
// init table is unreadable and that check always failed open. These rules read
// only the caller's own table, which is always available.
static constexpr jint MOUNT_RULE_NONE = 0;

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
                              std::string* moduleNameOut) {
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
    while (fgets(buf, sizeof(buf), mountinfo)) {
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
    std::vector<std::string> moduleNames;
    for (const std::string& line : lines) {
        std::string moduleName;
        result |= classifyMountLine(line, dataDev, &moduleName);
        if (!moduleName.empty()) moduleNames.push_back(moduleName);
    }

    static const char* kModuleNeedles[] = {
        "SiEjKD8iby4hIjgmQg==",   // zygisk_vector
        "SiEjKD8ibyssICEgWzc=",   // zygisk_shamiko
        "SiEjKD8ibzYhOTg=",       // zygisk_next
        "Qj0+OCsgQzM=",           // rezygisk
    };
    for (std::string name : moduleNames) {
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        for (const char* encoded : kModuleNeedles) {
            if (name.find(Deobfuscate(base64_decode(encoded))) != std::string::npos) {
                result |= DETECTION_ZYGISK;
            }
        }
    }

    return result;
}

static bool detectOverlayFS() {
    ScopedFile mountinfo(
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkXy0qNSUnVjc=")).c_str(), "r");
    if (!mountinfo.isOpen()) return false;

    char line[1024];
    while (fgets(line, sizeof(line), mountinfo)) {
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
    while (std::getline(maps, line)) {
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

static bool detectFridaPort() {
    if (tryConnectLoopback(27042) || tryConnectLoopback(27043))
        return true;

    std::string tcpFiles[] = {
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjgqQA==")),
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjgqQG4=")),
    };

    for (const auto& tcpFile : tcpFiles) {
        ScopedFile fp(tcpFile.c_str(), "r");
        if (!fp.isOpen()) continue;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, ":69A2") || strstr(line, ":69a2") ||
                strstr(line, ":69A3") || strstr(line, ":69a3"))
                return true;
        }
    }
    return false;
}

static bool detectFridaThreads() {
    DIR* taskDir = opendir("/proc/self/task");
    if (!taskDir) return false;

    struct dirent* entry;
    while ((entry = readdir(taskDir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        char commPath[256];
        snprintf(commPath, sizeof(commPath), "/proc/self/task/%s/comm", entry->d_name);

        ScopedFile fp(commPath, "r");
        if (!fp.isOpen()) continue;

        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), fp)) {
            if (strstr(comm, "gum-js-loop") || strstr(comm, "frida")) {
                closedir(taskDir);
                return true;
            }
        }
    }
    closedir(taskDir);

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("frida-agent") != std::string::npos ||
                line.find("frida-gadget") != std::string::npos ||
                line.find("libgadget") != std::string::npos) {
                maps.close();
                return true;
            }
        }
        maps.close();
    }
    return false;
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
        while (fgets(line, sizeof(line), fp)) {
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
        while (std::getline(maps, line)) {
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
        while (std::getline(maps, line)) {
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
        while (fgets(buf, sizeof(buf), mp)) content += buf;

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
        while (std::getline(maps, line)) {
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
    while (std::getline(maps, line)) {
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
        if (info) return true;
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
        if (access(p.c_str(), F_OK) == 0) return true;
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
        if (access(p.c_str(), F_OK) == 0) return true;
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
        if (access(p.c_str(), F_OK) == 0) return true;
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

    if (bootloader.find("unlock") != std::string::npos ||
        (!verified_boot_state.empty() && verified_boot_state != "green") ||
        veritymode == "disabled" ||
        flash_locked == "0")
        return true;

    std::string vbmeta_state = getProp(
        decodeProp(prop::kVbmetaDeviceState).c_str());
    if (!vbmeta_state.empty() && vbmeta_state != "locked") return true;

    std::string debuggable = getProp(
        decodeProp(prop::kDebuggable).c_str());
    if (debuggable == "1") return true;

    std::string secure = getProp(
        decodeProp(prop::kSecure).c_str());
    if (!secure.empty() && secure != "1") return true;

    std::string oem_unlock = getProp(
        decodeProp(prop::kOemUnlockAllowed).c_str());
    if (oem_unlock == "1") return true;

    return false;
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
JNIEXPORT jint JNICALL
f5d6d8a0228d2e7b607f28fefe95c77(JNIEnv *env, jobject , jobject obj) {
    jint result = 0;

    if (isTraced() == 1)
        result |= DETECTION_DEBUGGER;

    if (detectFridaPort() || detectFridaThreads())
        result |= DETECTION_FRIDA;

    if (detectSuspiciousParent() == 1)
        result |= DETECTION_FRIDA;

#ifndef IS_DEBUG_BUILD
    if (isAppDebuggable(env, obj))
        result |= DETECTION_DEBUGGER;
#endif

    std::vector<DetectionCheck> checks = {
        {0, [](JNIEnv* e, jobject o) -> jint {
            jint r = 0;

            if (isZygiskActiveEnhanced() ||
                detectSuBinary() || detectBusyBox() ||
                detectLegacyRootArtifacts() ||
                detectRootManagerApp(e, o))
                r |= DETECTION_ZYGISK;
            r |= detectMountArtifacts();
            if (detectOverlayFS() || detectRWXMappings())
                r |= DETECTION_ROOT_HIDER;
            return r;
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
    return result;
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
           DETECTION_ATTEST_SOFTWARE;
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
         const_cast<char*>("(Landroid/content/Context;)I"),
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
