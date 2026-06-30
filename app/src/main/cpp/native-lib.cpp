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

/*
 * RAII for JNI local references. The local-ref table defaults to 512 slots
 * per native frame; long-running detection paths used to leak refs on every
 * early-return branch. Wrapping every Find/Call/GetField in LocalRef makes
 * cleanup automatic regardless of exit point.
 */
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
            // ReZygisk, ZygiskNext, Shamiko, Zygisk Assistant, NoHello, LSPosed,
            // MagiskHide, and zygisk core libs / anon mappings.
            if (line.find("rezygisk") != std::string::npos ||
                line.find("zygisk_next") != std::string::npos ||
                line.find("libzygisk_") != std::string::npos ||
                line.find("libzygisk.so") != std::string::npos ||
                line.find("libmagiskhide.so") != std::string::npos ||
                line.find("zygisk_assistant") != std::string::npos ||
                line.find("nohello") != std::string::npos ||
                line.find("shamiko") != std::string::npos ||
                line.find("lspd") != std::string::npos ||
                line.find("LSPosed") != std::string::npos ||
                line.find("[anon:zygisk]") != std::string::npos) {
                maps.close();
                return true;
            }
        }
        maps.close();
    }

    // Zygisk/Magisk leak environment markers into hooked app processes.
    if (getenv("ZYGISK_ENABLED") != nullptr ||
        getenv("MAGISK_VER_CODE") != nullptr)
        return true;

    char prop[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.magisk.zygisk", prop);
    if (strlen(prop) > 0 && strcmp(prop, "0") != 0) return true;

    // Check Magisk module directories
    if (access("/data/adb/magisk", F_OK) == 0) return true;
    if (access("/data/adb/ksu", F_OK) == 0) return true;
    if (access("/data/adb/ap", F_OK) == 0) return true;

    return false;
}

__attribute__((always_inline))
static inline bool detectPIFSideEffects() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find(Deobfuscate(base64_decode("VStqIiQgRD02LiEoXnY0LS0wWTYwJCs7WSw9JyUx"))) != std::string::npos ||
                line.find(Deobfuscate(base64_decode("cy03NSMkez09EjgmQj0XMSU="))) != std::string::npos ||
                line.find(Deobfuscate(base64_decode("cy03NSMkYCorNyUtVSo="))) != std::string::npos ||
                line.find(Deobfuscate(base64_decode("YDQlOAUnRD0jMyU9SR4tOQ=="))) != std::string::npos ||
                line.find(Deobfuscate(base64_decode("QDQlOCUnRD0jMyU9ST4tOQ=="))) != std::string::npos ||
                line.find(Deobfuscate(base64_decode("YDQlOAUnRD0jMyU9SR4rMyc="))) != std::string::npos ||         // PlayIntegrityFork
                line.find(Deobfuscate(base64_decode("eTYJJCEmQiEAJDQKXDk3MgAmUTwhMw=="))) != std::string::npos || // InMemoryDexClassLoader
                line.find(Deobfuscate(base64_decode("azkqLiJzVDkoNyUiHRwBGQ=="))) != std::string::npos) {          // [anon:dalvik-DEX
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
        // PIFS KeyboxHub paths (auto-rotating keybox source, April 2026)
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mWz09IyMxWC0m")),  // /data/adb/modules/keyboxhub
        Deobfuscate(base64_decode("HzwlNS1mUTwmbicsSTorOWIxXTQ=")),          // /data/adb/keybox.xml
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

static bool detectPropertyInconsistencies() {
    char fingerprint[PROP_VALUE_MAX] = {0};
    char model[PROP_VALUE_MAX] = {0};
    char brand[PROP_VALUE_MAX] = {0};
    char device[PROP_VALUE_MAX] = {0};

    __system_property_get(
        Deobfuscate(base64_decode("QjdqIzkgXDxqJyUnVz02MT4gXiw=")).c_str(), fingerprint);
    __system_property_get(
        Deobfuscate(base64_decode("QjdqMT4mVC0nNWIkXzwhLQ==")).c_str(), model);
    __system_property_get(
        Deobfuscate(base64_decode("QjdqMT4mVC0nNWIrQjkqJQ==")).c_str(), brand);
    __system_property_get(
        Deobfuscate(base64_decode("QjdqMT4mVC0nNWItVS4tIik=")).c_str(), device);

    if (strlen(fingerprint) == 0) return false;

    std::string fp(fingerprint);

    // brand/product/device:version/... - cross-validate brand
    if (strlen(brand) > 0) {
        std::string fpBrand = fp.substr(0, fp.find('/'));
        if (!fpBrand.empty() && fpBrand != brand) return true;
    }

    /*
     * (Removed a security-patch-year vs /proc/version kernel-build-year
     * consistency check. It assumed the two are within ~2 years, but that is
     * false for a large class of GENUINE devices: LTS/backported kernels keep
     * their original build date while receiving current monthly patches, and
     * long-support flagships -- e.g. Pixels under Google's multi-year update
     * commitment -- routinely run a security patch level several years newer
     * than their kernel build. Both /proc/version and ro.build.version
     * .security_patch are world-readable, so this fired unprivileged and
     * false-positived on exactly the devices this app targets. It was also
     * non-deterministic by nature, so it had no place in a deterministic
     * signal set.)
     */

    /*
     * Hooked property reads have measurable overhead. 50ms threshold for
     * 100 reads tolerates thermal-throttled ARM cores under load -- the
     * old 10ms threshold false-positived on slow devices. On unhooked
     * Android the same loop runs in 1-2ms, so 50ms still has 25x headroom
     * before flagging.
     */
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        char tmp[PROP_VALUE_MAX] = {0};
        __system_property_get("ro.build.fingerprint", tmp);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    if (duration > 50000) return true;

    /*
     * Motherboard spoof check (PIFS April 2026): tryigit's PIFS rewrites
     * ro.product.board to a Pixel motherboard but the kernel-exposed
     * Hardware line in /proc/cpuinfo still reports the original SoC.
     * Pixels run on Tensor (gs101/gs201/zuma/zumapro), so a Pixel board
     * with non-Tensor cpuinfo is a strong spoof signal.
     */
    char board[PROP_VALUE_MAX] = {0};
    __system_property_get(
        Deobfuscate(base64_decode("QjdqMT4mVC0nNWIrXzk2JQ==")).c_str(), board);

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

            if (!cpuHardware.empty()) {
                std::string b(board);
                std::transform(b.begin(), b.end(), b.begin(), ::tolower);
                std::string h = cpuHardware;
                std::transform(h.begin(), h.end(), h.begin(), ::tolower);

                static const char* pixelBoards[] = {
                    "panther", "cheetah", "lynx", "felix", "tangorpro",
                    "shiba", "husky", "akita", "comet", "tegu",
                    "tokay", "caiman", "komodo", "redondo"
                };
                for (const char* pb : pixelBoards) {
                    if (b.find(pb) != std::string::npos) {
                        // Pixel boards must run on Tensor SoCs
                        if (h.find("tensor") == std::string::npos &&
                            h.find("gs101") == std::string::npos &&
                            h.find("gs201") == std::string::npos &&
                            h.find("zuma") == std::string::npos) {
                            return true;
                        }
                        break;
                    }
                }
            }
        }
    }

    return false;
}

static bool detectMountNS() {
    ScopedFile selfMounts(
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkXy0qNT8=")).c_str(), "r");
    ScopedFile initMounts(
        Deobfuscate(base64_decode("Hyg2Li9mAXcpLjknRCs=")).c_str(), "r");

    if (!selfMounts.isOpen() || !initMounts.isOpen())
        return false;

    int selfCount = 0, initCount = 0;
    char line[1024];
    while (fgets(line, sizeof(line), selfMounts)) selfCount++;
    while (fgets(line, sizeof(line), initMounts)) initCount++;

    if (initCount > 0 && selfCount > 0 && (initCount - selfCount) > 5)
        return true;

    return false;
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

static bool detectSELinuxAnomaly() {
    ScopedFile ctx(
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MoRCw2bi88QiohLzg=")).c_str(), "r");
    if (!ctx.isOpen()) return false;

    char context[256] = {0};
    size_t bytesRead = fread(context, 1, sizeof(context) - 1, ctx);
    context[bytesRead] = '\0';

    if (strstr(context, "magisk") || strstr(context, "zygisk"))
        return true;

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
        // Whitelist legitimate JIT/ART/allocator anon regions that can be rwx
        // on genuine devices (ART JIT, Unity/Flutter/V8 engines) to avoid
        // false-positiving real hardware.
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

/*
 * Android 10+ filters /proc/net/tcp to empty for untrusted_app via SELinux,
 * so the legacy procfs scan can't see a root-owned frida-server socket.
 * A TCP connect to localhost is allowed for untrusted apps; if the port
 * is listening, connect() returns 0. We probe 27042 (default frida-server
 * control) and 27043 (D-Bus side channel some builds expose).
 */
static bool tryConnectLoopback(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

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
        timeval tv{0, 200000}; // 200 ms
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

    // Fallback: legacy procfs scan -- harmless on Android 10+ (returns empty)
    // but still works on older devices and on systems where the SELinux
    // policy doesn't filter /proc/net/tcp for untrusted apps.
    std::string tcpFiles[] = {
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjgqQA==")),
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjgqQG4=")),
    };

    for (const auto& tcpFile : tcpFiles) {
        ScopedFile fp(tcpFile.c_str(), "r");
        if (!fp.isOpen()) continue;

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, ":69A2") || strstr(line, ":69a2"))
                return true;
        }
    }
    return false;
}

/*
 * Scope: scans /proc/self/task -- catches Frida-gadget INJECTED into our
 * own process (libgadget creates threads named gmain/gum-js-loop/frida-*).
 * An external frida-server attached over the control port does NOT show
 * up here; that case is covered by detectFridaPort()'s TCP probe.
 */
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
            // Note: the bare GLib thread name "gmain" is intentionally NOT
            // matched -- it false-positives on legitimate GLib-based libs.
            if (strstr(comm, "gum-js-loop") || strstr(comm, "frida")) {
                closedir(taskDir);
                return true;
            }
        }
    }
    closedir(taskDir);

    // Frida gadget injected into our own process leaves a mapped library --
    // this is the in-process signature the (now-removed) VM check targeted.
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));  // /proc/self/maps
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

/*
 * Detects KOWX712/PlayIntegrityFix inject-s technique (v4.5 March 2026,
 * v4.6 June 2026 confirmed same architecture): the classes.dex payload is
 * streamed over a Zygisk companion IPC channel and loaded via
 * InMemoryDexClassLoader, dropping the on-disk JSON config older detectors
 * looked for (v4.6 ships pif.prop, never pif.json).
 *
 * PRIVILEGE BOUNDARY (verified against v4.6 source): the injection happens
 * inside the GMS DroidGuard process, NOT this app's process, and the companion
 * channel uses the Zygisk implementation's own internal (randomized) socket --
 * the module never names its own socket. So neither the companion socket nor
 * the memfd-backed dex appears in THIS process's /proc/self/net/unix or
 * /proc/self/maps, and the /data/adb/modules/ probes are SELinux-denied to an
 * unprivileged untrusted_app. These checks therefore only fire when the
 * detector runs privileged (root/adb) or against a misconfigured global
 * spoofer. For the unprivileged product the load-bearing inject-s signal is
 * ATTEST_ANOMALY (the spoofed CustomKeyStoreSpi/CustomProvider + keybox chain),
 * not this function.
 */
static bool detectCompanionStreaming() {
    // Best-effort, privileged-only: a system-wide unix-socket scan. SELinux
    // filters /proc/net/unix to empty for untrusted_app on Android 10+, and
    // the real Zygisk companion channel is not module-named, so this catches
    // only naive custom modules that name their own abstract socket.
    std::string unixPaths[] = {
        Deobfuscate(base64_decode("Hyg2Li9mXj0wbjknWSA=")),       // /proc/net/unix
        Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MnVSxrNCIgSA==")) // /proc/self/net/unix
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

    /*
     * memfd_create-backed mappings. Android 9+ ART legitimately uses memfd
     * for jit-cache, dalvik-* regions, so we can only flag memfd regions
     * that are BOTH rwxp (writable + executable, rare for legit code) AND
     * not tagged with any known ART allocator name. Streamed DEX payloads
     * tend to land as unnamed memfds or memfd:<custom> with rwxp.
     */
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("memfd:") == std::string::npos) continue;
            if (line.find("rwxp") == std::string::npos) continue;

            // Whitelist known ART allocator names
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

    /*
     * inject-s v4.5 signature: module installed but no pif.json config.
     * Older PIF + the inject branch always shipped a config file. v4.5
     * dropped the JSON format entirely.
     */
    std::string moduleDir =
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOQ=="));
    std::string forkZygiskDir =
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4rMydmSiEjKD8i"));

    // (Removed a check for a ".../playintegrityfix/companion" directory: no
    // inject-s version creates that dir -- "companion" is a registered Zygisk
    // function, not a module folder -- so the probe could never match.)
    if (access(forkZygiskDir.c_str(), F_OK) == 0) return true;

    if (access(moduleDir.c_str(), F_OK) == 0) {
        std::string jsonPath = moduleDir + "/pif.json";
        std::string customPath = moduleDir + "/custom.pif.json";
        if (access(jsonPath.c_str(), F_OK) != 0 &&
            access(customPath.c_str(), F_OK) != 0) {
            return true;  // module live with no JSON -> v4.5 lightweight format
        }
    }

    return false;
}

/*
 * Detects osm0sis PlayIntegrityFork autopif4 (Jan 2026) technique:
 * monthly Pixel Canary build fingerprints. Canary IDs follow a strict
 * format and rotate monthly to dodge fingerprint blacklists, but autopif4
 * only spoofs ro.build.* -- the vendor and system partitions still leak
 * the original build identity.
 *
 * All checks are gated on the fingerprint claiming to be a Google Pixel
 * (`google/...`). Non-Google OEMs legitimately ship with different vendor
 * vs system partition build IDs (e.g. Samsung's vendor may be 2 Android
 * versions behind) and use Android-standard build ID formats like
 * UP1A.231005.007, so we cannot apply these checks cross-vendor.
 */
static bool detectPixelCanaryFingerprint() {
    char fingerprint[PROP_VALUE_MAX] = {0};
    char buildId[PROP_VALUE_MAX] = {0};
    char sysBuildId[PROP_VALUE_MAX] = {0};
    char brand[PROP_VALUE_MAX] = {0};

    __system_property_get(
        Deobfuscate(base64_decode("QjdqIzkgXDxqJyUnVz02MT4gXiw=")).c_str(), fingerprint);
    __system_property_get(
        Deobfuscate(base64_decode("QjdqIzkgXDxqKCg=")).c_str(), buildId);
    __system_property_get(
        Deobfuscate(base64_decode("QjdqMjU6RD0pby48WTQgbyUt")).c_str(), sysBuildId);
    __system_property_get(
        Deobfuscate(base64_decode("QjdqMT4mVC0nNWIrQjkqJQ==")).c_str(), brand);

    if (strlen(fingerprint) == 0 || strlen(buildId) == 0) return false;

    std::string fp(fingerprint);
    std::string id(buildId);

    /* Gate: fingerprint must claim to be a Pixel build. Non-Google brands
     * that claim google/ anywhere in the fingerprint are a direct spoof. */
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

    /* From here fingerprint starts with "google/". Real Pixels report
     * brand=google; anything else is a spoof. */
    if (strlen(brand) > 0) {
        std::string b(brand);
        std::transform(b.begin(), b.end(), b.begin(), ::tolower);
        if (b != "google") return true;
    }

    /* autopif4 spoofs ro.build.id but ro.system.build.id stays original */
    if (strlen(sysBuildId) > 0 && strcmp(buildId, sysBuildId) != 0) {
        return true;
    }

    /* Canary build ID format: 2 letters + digit + alnum + . + 6 digits + . + 3 digits
     * e.g. BP31.250307.001, AP4A.250605.005, ZP3A.260118.012. Note this also
     * matches Android-standard release IDs like UP1A.231005.007, so we only
     * apply the vendor-leak check after confirming the fingerprint is Pixel. */
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
        /* On a legit Pixel the vendor partition fp must reference the same
         * build ID. autopif4 only touches top-level, leaving vendor at the
         * original build. */
        char vendorFp[PROP_VALUE_MAX] = {0};
        __system_property_get("ro.vendor.build.fingerprint", vendorFp);
        if (strlen(vendorFp) > 0) {
            std::string vfp(vendorFp);
            if (vfp.find(id) == std::string::npos) return true;
        }
    }

    /* Real Pixel fingerprints always embed ro.build.id. PIFS sometimes
     * spoofs only the fingerprint string without updating ro.build.id. */
    if (fp.find(id) == std::string::npos) return true;

    return false;
}

/*
 * XtrLumen/TS-Enhancer-Extreme (May 2026): an active anti-detection module
 * that masquerades the bootloader as locked, fakes VerifiedBootHash, and
 * takes over TrickyStore's target.txt. The module deploys at a fixed
 * path with a config dir at /data/adb/ts_enhancer_extreme, and ships
 * Rust-built CLI/dylib components (tseed/tsees/tseev) whose strings
 * leak into /proc/self/maps.
 */
static bool detectTSEnhancerExtreme() {
    const std::string paths[] = {
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
            Deobfuscate(base64_decode("RCsbJCIhUTYnJD4WVSAwMykkVQ==")),  // ts_enhancer_extreme
            Deobfuscate(base64_decode("ZAsBLyQoXjshMwkxRCohLCk=")),      // TSEnhancerExtreme
            // (Dropped "tseedemo": verified against XtrLumen/TS-Enhancer-Extreme
            //  -- no such string exists in the module; it was speculative.)
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

/*
 * Enginex0/PlayIntegrityFix-Hybrid (May 2026, also mirrored by sad25kag):
 * pure-Rust rewrite of PIF
 * with no DobbyHook dependency, so the existing libdobby/InMemoryDexClassLoader
 * signatures don't catch it. The module reuses the upstream module id
 * (`playintegrityfix`), so we fingerprint by reading module.prop content
 * (description / author markers) and by scanning maps for Rust crate libs.
 */
static bool detectRustPIF() {
    ScopedFile mp(
        Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOWMkXzwxLSlnQCorMQ==")).c_str(),
        "r");
    if (mp.isOpen()) {
        std::string content;
        char buf[256];
        while (fgets(buf, sizeof(buf), mp)) content += buf;

        const std::string markers[] = {
            Deobfuscate(base64_decode("YC02JGwbRSswYQktWSwtLiI=")),  // Pure Rust Edition
            Deobfuscate(base64_decode("Sj02LmwNXzomOAQmXzM=")),      // zero DobbyHook
            Deobfuscate(base64_decode("dTYjKCIsSGg=")),              // Enginex0
            Deobfuscate(base64_decode("YDQlOAUnRD0jMyU9SR4tOWEBSTo2KCg=")),  // PlayIntegrityFix-Hybrid
        };
        for (const auto& m : markers) {
            if (content.find(m) != std::string::npos) return true;
        }
    }

    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (maps.is_open()) {
        const std::string libs[] = {
            Deobfuscate(base64_decode("XDEmMSUvbzUrJTklVXY3Lg==")),  // libpif_module.so
            // (Dropped "libresetprop.so": verified against the Enginex0
            //  PlayIntegrityFix-Hybrid source -- the resetprop crate is an
            //  rlib/CLI binary "resetprop-rs", never a loaded .so, so this
            //  token would never appear in /proc/self/maps. libpif_module.so
            //  is the real cdylib loaded into the process.)
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

/*
 * Treat Wheel (May 2026): a "Shamiko for ReZygisk" root hider (now open at
 * PerformanC/Treat-Wheel-Zygisk; was Telegram-only),
 * written in C to dodge the __cxa_atexit / g_array zeroed-handler detection
 * vector that catches C++ Zygisk modules on unload. It reads maps/mountinfo
 * through a fork+socketpair child to defeat "procfs opened before app start"
 * heuristics. None of that hides its own mapping name, though: the module
 * still loads into our process from a path containing "treat_wheel/zygisk/",
 * so a /proc/self/maps substring scan in-process catches it. Fully in-process,
 * so it survives Android 10+ SELinux. Only pairs with ReZygisk (not Zygisk Next).
 *
 * Matching the bare "treat_wheel" token (rather than the full path) keeps this
 * robust to module-layout changes and is FP-safe -- the token would never
 * legitimately appear in a clean app's maps.
 */
static bool detectTreatWheel() {
    std::ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    const std::string needle = Deobfuscate(base64_decode("RCohIDgWRzAhJCA="));  // treat_wheel
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

/*
 * Untrusted apps can't access() paths under /data/adb on Android 10+, so the existing
 * isZygiskActiveEnhanced() path checks return false against installed root
 * managers that aren't injected into our process. PackageManager is always
 * reachable. We probe the well-known root manager packages plus a few hide
 * variants. A NameNotFoundException is normal -- catch and continue.
 *
 * Fail-open by design (returns false on JNI lookup failure). This function
 * is one of multiple Zygisk signals; a hooked-JNI environment that breaks
 * PackageManager lookups is still caught by isZygiskActiveEnhanced(),
 * detectSuBinary(), detectBusyBox(), detectLegacyRootArtifacts(), or the
 * VM-based Zygisk check. Fail-closing here would cause every device to
 * trip the Zygisk bit if Context.getPackageManager became unreachable
 * for any reason (e.g., transient Binder failure).
 */
static bool detectRootManagerApp(JNIEnv *env, jobject context) {
    static const std::string pkgs[] = {
        // Modern root managers
        Deobfuscate(base64_decode("UzcpbzgmQDIrKSI+RXYpICsgQzM=")),         // com.topjohnwu.magisk
        Deobfuscate(base64_decode("WTdqJiU9WC0mbyQ8QzM9JStnXTkjKD8i")),     // io.github.huskydg.magisk
        Deobfuscate(base64_decode("WTdqJiU9WC0mbzo/Ump0d3xnXTkjKD8i")),     // io.github.vvb2060.magisk
        Deobfuscate(base64_decode("XT1qNikgQzAxbycsQjYhLT88")),             // me.weishu.kernelsu
        Deobfuscate(base64_decode("XT1qIyEoSHYlMS09UzA=")),                 // me.bmax.apatch
        Deobfuscate(base64_decode("Uzcpbz4gVis8JWIiQy0qJDQ9")),             // com.rifsxd.ksunext
        // Classic SuperUser apps (legacy but still on some devices)
        Deobfuscate(base64_decode("UzcpbycmRSssKCctRSwwIGI6RSghMzk6VSo=")), // com.koushikdutta.superuser
        Deobfuscate(base64_decode("UzcpbyImQzAxJyM8HjkqJT4mWTxqMjk=")),     // com.noshufou.android.su
        Deobfuscate(base64_decode("VS1qIiQoWTYiKD4sHisxMSk7Qy0=")),         // eu.chainfire.supersu
        Deobfuscate(base64_decode("UzcpbycgXj8rND8sQnYnLiE=")),             // com.kingouser.com
        // Root-cloaker apps -- presence implies the user is hiding root
        Deobfuscate(base64_decode("UzcpbygsRjkgNy0nUz1qMyMmRDsoLi0i")),     // com.devadvance.rootcloak
        Deobfuscate(base64_decode("UzcpbygsRjkgNy0nUz1qMyMmRDsoLi0iAg==")), // com.devadvance.rootcloak2
        Deobfuscate(base64_decode("UzcpbyomQjU9KSFnWDEgJD4mXyw=")),         // com.formyhm.hideroot
        Deobfuscate(base64_decode("Uzcpby0kQDArMy06HjAtJSkkSSorLjg=")),     // com.amphoras.hidemyroot
    };

    LocalRef<jclass> contextClass(env, env->FindClass("android/content/Context"));
    if (!contextClass) return false;

    jmethodID getPM = env->GetMethodID(contextClass, "getPackageManager",
        "()Landroid/content/pm/PackageManager;");
    if (!getPM) return false;

    LocalRef<jobject> pm(env, env->CallObjectMethod(context, getPM));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!pm) return false;

    LocalRef<jclass> pmClass(env, env->FindClass("android/content/pm/PackageManager"));
    if (!pmClass) return false;

    jmethodID getPkgInfo = env->GetMethodID(pmClass, "getPackageInfo",
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

/*
 * Su-binary path scan. Originally folded into the VM bytecode for legacy
 * paths only; modern setups install to /system_ext/bin/su (Android 11+
 * system_ext partition) which the legacy list misses. access() to these
 * specific files is allowed for untrusted apps -- only directory listing
 * under /data/adb is blocked.
 */
static bool detectSuBinary() {
    static const std::string paths[] = {
        Deobfuscate(base64_decode("Hys9MjgsXXcmKCJmQy0=")),         // /system/bin/su
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHysx")),         // /system/xbin/su
        Deobfuscate(base64_decode("HysmKCJmQy0=")),                 // /sbin/su
        Deobfuscate(base64_decode("Hys9MjgsXQchOThmUjEqbj88")),     // /system_ext/bin/su
        Deobfuscate(base64_decode("Hy4hLygmQncmKCJmQy0=")),         // /vendor/bin/su
        Deobfuscate(base64_decode("HzcgLGMrWTZrMjk=")),             // /odm/bin/su
        Deobfuscate(base64_decode("Hyg2Lig8UyxrIyUnHysx")),         // /product/bin/su
        Deobfuscate(base64_decode("HzUlJiU6W3dqIiM7VXcmKCJmQy0=")), // /magisk/.core/bin/su
        Deobfuscate(base64_decode("HzwlNS1mXDcnICBmRDU0bj88")),     // /data/local/tmp/su
    };
    for (const auto& p : paths) {
        if (access(p.c_str(), F_OK) == 0) return true;
    }
    return false;
}

/*
 * BusyBox is the userland multitool every classic root install drops
 * somewhere on the filesystem. Magisk doesn't ship busybox by default
 * anymore but plenty of older / custom setups do, and a busybox sitting
 * in /system/xbin without a release-keys vendor signature is a strong
 * tampering indicator on its own.
 */
static bool detectBusyBox() {
    static const std::string paths[] = {
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHzoxMjUrXyA=")),   // /system/xbin/busybox
        Deobfuscate(base64_decode("Hys9MjgsXXcmKCJmUi03OC4mSA==")),   // /system/bin/busybox
        Deobfuscate(base64_decode("Hys9MjgsXXc3IyUnHzoxMjUrXyA=")),   // /system/sbin/busybox
        Deobfuscate(base64_decode("HysmKCJmUi03OC4mSA==")),           // /sbin/busybox
        Deobfuscate(base64_decode("Hy4hLygmQncmKCJmUi03OC4mSA==")),   // /vendor/bin/busybox
        Deobfuscate(base64_decode("HzwlNS1mXDcnICBmUi03OC4mSA==")),   // /data/local/busybox
        Deobfuscate(base64_decode("HzwlNS1mXDcnICBmSDotL2MrRSs9IyMx")),// /data/local/xbin/busybox
    };
    for (const auto& p : paths) {
        if (access(p.c_str(), F_OK) == 0) return true;
    }
    return false;
}

/*
 * Pre-Magisk SuperUser/SuperSU installations dropped manager APKs and
 * daemon scripts directly into /system. These paths are world-readable,
 * not under /data/adb, so untrusted_app's access() reaches them.
 * Modern Magisk hides itself entirely but legacy/dirty roots still
 * leave these breadcrumbs.
 */
static bool detectLegacyRootArtifacts() {
    static const std::string paths[] = {
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD48Qz02by05Ww==")),        // /system/app/Superuser.apk
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD4aZXYlMSc=")),            // /system/app/SuperSU.apk
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmezEqJjk6VSpqIDwi")),            // /system/app/Kinguser.apk
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD48Qz02")),                // /system/app/Superuser
        Deobfuscate(base64_decode("Hys9MjgsXXclMTxmYy00JD4aZQ==")),                // /system/app/SuperSU
        Deobfuscate(base64_decode("Hys9MjgsXXc0MyU/HTk0MWMaRSghMzk6VSpqIDwi")),    // /system/priv-app/Superuser.apk
        Deobfuscate(base64_decode("Hys9MjgsXXchNS9mWTYtNWItH2F9Ejk5VSoXFAgoVTUrLw==")), // /system/etc/init.d/99SuperSUDaemon
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHzwlJCEmXisx")),                // /system/xbin/daemonsu
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHysxJiM9VQ==")),                // /system/xbin/sugote
        Deobfuscate(base64_decode("Hys9MjgsXXc8IyUnHysxbyg=")),                    // /system/xbin/su.d
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
    std::string verified_boot_state = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYyJD4gVjEhJS4mXyw3NS09VQ==")).c_str());
    std::string bootloader         = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYmLiM9XDclJSk7")).c_str());
    std::string veritymode         = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYyJD4gVzpmLiAtEg==")).c_str());
    std::string flash_locked       = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYmXDkmJylmXCcrQj0s")).c_str());

    if (bootloader.find("unlock") != std::string::npos ||
        (!verified_boot_state.empty() && verified_boot_state != "green") ||
        veritymode == "disabled" ||
        flash_locked == "0")
        return true;

    std::string vbmeta_state = getProp(
        Deobfuscate(base64_decode("QjdqIyMmRHYyIyEsRDlqJSk/WTshHj89USwh")).c_str());
    if (!vbmeta_state.empty() && vbmeta_state != "locked") return true;

    std::string debuggable = getProp(
        Deobfuscate(base64_decode("QjdqJSkrRT8jIC4lVQ==")).c_str());
    if (debuggable == "1") return true;

    std::string secure = getProp(
        Deobfuscate(base64_decode("QjdqMikqRSoh")).c_str());
    if (!secure.empty() && secure != "1") return true;

    std::string oem_unlock = getProp(
        Deobfuscate(base64_decode("QyE3byMsXQcxLyAmUzMbICAlXy8hJQ==")).c_str());
    if (oem_unlock == "1") return true;

    return false;
}

/*
 * Fail-closed: any JNI lookup failure returns true ("debuggable"), so a
 * hostile environment that breaks Context lookups can't suppress the
 * DETECTION_DEBUGGER bit by hooking JNI.
 */
static bool isAppDebuggable(JNIEnv *env, jobject context) {
    LocalRef<jclass> contextClass(env, env->FindClass("android/content/Context"));
    if (!contextClass) return true;

    jmethodID getAppInfo = env->GetMethodID(contextClass, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    if (!getAppInfo) return true;

    LocalRef<jobject> appInfo(env, env->CallObjectMethod(context, getAppInfo));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return true; }
    if (!appInfo) return true;

    LocalRef<jclass> appInfoClass(env, env->FindClass("android/content/pm/ApplicationInfo"));
    if (!appInfoClass) return true;

    jfieldID flagsField = env->GetFieldID(appInfoClass, "flags", "I");
    if (!flagsField) return true;

    jint flags = env->GetIntField(appInfo, flagsField);
    return (flags & 0x2) != 0;
}

/*
 * Compute SHA-256 of a byte[] via java.security.MessageDigest. Returns
 * the digest as a lowercase hex string, or empty on failure.
 */
static std::string sha256Hex(JNIEnv *env, jbyteArray bytes) {
    LocalRef<jclass> mdClass(env, env->FindClass("java/security/MessageDigest"));
    if (!mdClass) return "";

    jmethodID getInstance = env->GetStaticMethodID(mdClass,
        "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!getInstance) return "";

    LocalRef<jstring> algo(env, env->NewStringUTF("SHA-256"));
    LocalRef<jobject> md(env, env->CallStaticObjectMethod(mdClass, getInstance, algo.get()));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    if (!md) return "";

    jmethodID digest = env->GetMethodID(mdClass, "digest", "([B)[B");
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

/*
 * Verifies the APK signing certificate by SHA-256 of the cert DER bytes,
 * obtained through PackageManager.GET_SIGNING_CERTIFICATES (API 28+).
 * Returns true iff the digest matches EXPECTED_CERT_SHA256.
 *
 * Fail-closed: every JNI lookup or call failure returns false so a hooked
 * environment cannot suppress DETECTION_SIGNATURE. The legacy hashCode()
 * comparison was 32-bit and trivially collidable.
 *
 * Debug builds skip the check (return true unconditionally) because debug
 * keystores are per-developer and shipping a fixed digest would break
 * everyone else's workflow.
 */
static bool verifyAPKSignature(JNIEnv *env, jobject context) {
#ifdef IS_DEBUG_BUILD
    (void)env; (void)context;
    return true;
#else
    // Lowercase hex SHA-256 of the production signing cert's DER bytes.
    // Update when rotating release signing keys.
    static const char EXPECTED_CERT_SHA256[] =
        "dd89407aca3619b91e12260009bed1a16a6c13775fcb39802c733564a0997426";

    LocalRef<jclass> contextClass(env, env->FindClass("android/content/Context"));
    if (!contextClass) return false;

    jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName",
        "()Ljava/lang/String;");
    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager",
        "()Landroid/content/pm/PackageManager;");
    if (!getPackageName || !getPackageManager) return false;

    LocalRef<jstring> packageName(env,
        (jstring)env->CallObjectMethod(context, getPackageName));
    LocalRef<jobject> pm(env, env->CallObjectMethod(context, getPackageManager));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!packageName || !pm) return false;

    LocalRef<jclass> pmClass(env, env->FindClass("android/content/pm/PackageManager"));
    if (!pmClass) return false;

    jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPackageInfo) return false;

    // PackageManager.GET_SIGNING_CERTIFICATES = 0x08000000 (API 28+)
    LocalRef<jobject> packageInfo(env,
        env->CallObjectMethod(pm, getPackageInfo, packageName.get(), 0x08000000));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!packageInfo) return false;

    LocalRef<jclass> piClass(env, env->FindClass("android/content/pm/PackageInfo"));
    if (!piClass) return false;

    jfieldID signingInfoField = env->GetFieldID(piClass, "signingInfo",
        "Landroid/content/pm/SigningInfo;");
    if (!signingInfoField) return false;

    LocalRef<jobject> signingInfo(env, env->GetObjectField(packageInfo, signingInfoField));
    if (!signingInfo) return false;

    LocalRef<jclass> siClass(env, env->FindClass("android/content/pm/SigningInfo"));
    if (!siClass) return false;

    jmethodID getSigners = env->GetMethodID(siClass,
        "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
    if (!getSigners) return false;

    LocalRef<jobjectArray> signatures(env,
        (jobjectArray)env->CallObjectMethod(signingInfo, getSigners));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!signatures || env->GetArrayLength(signatures) == 0) return false;

    LocalRef<jobject> sig(env, env->GetObjectArrayElement(signatures, 0));
    if (!sig) return false;

    LocalRef<jclass> sigClass(env, env->FindClass("android/content/pm/Signature"));
    if (!sigClass) return false;

    jmethodID toByteArray = env->GetMethodID(sigClass, "toByteArray", "()[B");
    if (!toByteArray) return false;

    LocalRef<jbyteArray> sigBytes(env,
        (jbyteArray)env->CallObjectMethod(sig, toByteArray));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!sigBytes) return false;

    std::string actual = sha256Hex(env, sigBytes);
    if (actual.empty()) return false;

    return actual == EXPECTED_CERT_SHA256;
#endif
}

static constexpr jint DETECTION_DEBUGGER    = 0x001;
static constexpr jint DETECTION_FRIDA       = 0x002;
static constexpr jint DETECTION_ZYGISK      = 0x004;
static constexpr jint DETECTION_PIF         = 0x008;
static constexpr jint DETECTION_BOOTLOADER  = 0x010;
static constexpr jint DETECTION_SIGNATURE   = 0x020;
static constexpr jint DETECTION_TRICKYSTORE = 0x040;
static constexpr jint DETECTION_PROP_SPOOF  = 0x080;
static constexpr jint DETECTION_ROOT_HIDER  = 0x100;
static constexpr jint DETECTION_PIF_STREAM  = 0x200;  // inject-s v4.5 companion-IPC streaming
static constexpr jint DETECTION_CANARY_FP   = 0x400;  // autopif4 Pixel Canary fingerprint
static constexpr jint DETECTION_TSEE        = 0x800;  // TS-Enhancer-Extreme anti-detection module
static constexpr jint DETECTION_PIF_RUST    = 0x1000; // PIF-Hybrid pure-Rust edition (no DobbyHook)
static constexpr jint DETECTION_TREAT_WHEEL = 0x2000; // Treat Wheel ReZygisk root hider
/*
 * Produced Kotlin-side by KeyAttestationProbe (the AndroidKeyStore attestation
 * API lives in Java land), never set by this engine. Registered here only so
 * nativeAllFlagsMask() stays the single source of truth for the full set of
 * defined flag bits and the Kotlin SSOT assertion still matches.
 */
static constexpr jint DETECTION_ATTEST_ANOMALY = 0x4000;

struct DetectionCheck {
    int id;
    std::function<jint(JNIEnv*, jobject)> check;
};

extern "C"
JNIEXPORT jint JNICALL
f5d6d8a0228d2e7b607f28fefe95c77(JNIEnv *env, jobject obj) {
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

    // randomize execution order
    std::vector<DetectionCheck> checks = {
        {0, [](JNIEnv* e, jobject o) -> jint {
            jint r = 0;
            // test-keys / userdebug check intentionally not in this chain --
            // it false-positives on legitimate Pixel userdebug devices that
            // are not rooted. The other signals catch real root setups.
            if (isZygiskActiveEnhanced() ||
                detectSuBinary() || detectBusyBox() ||
                detectLegacyRootArtifacts() ||
                detectRootManagerApp(e, o))
                r |= DETECTION_ZYGISK;
            if (detectMountNS() || detectOverlayFS() ||
                detectSELinuxAnomaly() || detectRWXMappings())
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

/*
 * Single source of truth for the bitmask. Kotlin keeps named constants
 * for ergonomics; this getter lets a runtime/test check assert the
 * Kotlin OR matches the native OR. If anyone adds a flag in only one
 * place, the assertion fires.
 */
extern "C"
JNIEXPORT jint JNICALL
nativeAllFlagsMaskImpl(JNIEnv *, jobject) {
    return DETECTION_DEBUGGER | DETECTION_FRIDA | DETECTION_ZYGISK |
           DETECTION_PIF | DETECTION_BOOTLOADER | DETECTION_SIGNATURE |
           DETECTION_TRICKYSTORE | DETECTION_PROP_SPOOF | DETECTION_ROOT_HIDER |
           DETECTION_PIF_STREAM | DETECTION_CANARY_FP |
           DETECTION_TSEE | DETECTION_PIF_RUST | DETECTION_TREAT_WHEEL |
           DETECTION_ATTEST_ANOMALY;
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

    jclass clazz = env->FindClass(className.c_str());
    if (!clazz)
        return JNI_ERR;

    static const JNINativeMethod methods[] = {
        {const_cast<char*>(methodName.c_str()),
         const_cast<char*>("()I"),
         reinterpret_cast<void *>(f5d6d8a0228d2e7b607f28fefe95c77)},
        {const_cast<char*>(maskMethodName.c_str()),
         const_cast<char*>("()I"),
         reinterpret_cast<void *>(nativeAllFlagsMaskImpl)},
    };

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) < 0)
        return JNI_ERR;

    return JNI_VERSION_1_6;
}
