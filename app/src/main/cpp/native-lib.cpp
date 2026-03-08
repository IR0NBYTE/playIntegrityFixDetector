#include <jni.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sys/system_properties.h>
#include <vector>
#include <map>
#include <memory>
#include <cstring>

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

static constexpr uint8_t VM_OBFUSCATION_KEY = 0x5A;

enum VMOpcode : uint8_t {
    OP_PUSH_IMM8        = 0x01,
    OP_PUSH_IMM32       = 0x02,
    OP_PUSH_STR         = 0x03,
    OP_POP              = 0x04,
    OP_DUP              = 0x05,
    OP_SWAP             = 0x06,

    OP_LOAD_REG         = 0x10,
    OP_STORE_REG        = 0x11,
    OP_CLEAR_REG        = 0x12,

    OP_ADD              = 0x20,
    OP_SUB              = 0x21,
    OP_XOR              = 0x22,
    OP_AND              = 0x23,
    OP_OR               = 0x24,
    OP_NOT              = 0x25,

    OP_CMP_EQ           = 0x30,
    OP_CMP_NEQ          = 0x31,
    OP_CMP_GT           = 0x32,
    OP_CMP_LT           = 0x33,

    OP_JUMP             = 0x40,
    OP_JUMP_IF_TRUE     = 0x41,
    OP_JUMP_IF_FALSE    = 0x42,
    OP_CALL             = 0x43,
    OP_RET              = 0x44,

    OP_FILE_OPEN        = 0x50,
    OP_FILE_CLOSE       = 0x51,
    OP_FILE_READ_LINE   = 0x52,
    OP_FILE_EXISTS      = 0x53,
    OP_FILE_EOF         = 0x54,

    OP_STR_CONTAINS     = 0x60,
    OP_STR_COMPARE      = 0x61,
    OP_STR_LENGTH       = 0x62,
    OP_STR_CONCAT       = 0x63,
    OP_STR_DECODE       = 0x64,

    OP_SYS_PROP_GET     = 0x70,
    OP_SYS_GETENV       = 0x71,
    OP_SYS_ACCESS       = 0x72,

    OP_NOP              = 0x80,
    OP_HALT             = 0x81,
    OP_DEBUG_CHECK      = 0x82,
};

struct VMState {
    std::vector<int64_t> stack;
    std::vector<std::string> stringStack;
    std::map<uint8_t, int64_t> registers;
    std::map<uint8_t, FILE*> fileHandles;
    std::vector<size_t> callStack;
    size_t ip;
    bool halted;
    uint8_t nextFileHandle;

    VMState() : ip(0), halted(false), nextFileHandle(1) {}

    ~VMState() {
        for (auto& fh : fileHandles) {
            if (fh.second) fclose(fh.second);
        }
    }
};

class SecureVM {
private:
    VMState state;
    std::vector<uint8_t> bytecode;
    std::vector<std::string> stringPool;

    uint8_t decodeOpcode(uint8_t encoded) {
        return encoded ^ VM_OBFUSCATION_KEY;
    }

public:
    SecureVM(const std::vector<uint8_t>& code, const std::vector<std::string>& strings)
        : bytecode(code), stringPool(strings) {}

    bool execute() {
        state.ip = 0;
        state.halted = false;

        while (state.ip < bytecode.size() && !state.halted) {
            uint8_t rawOpcode = bytecode[state.ip++];
            uint8_t opcode = decodeOpcode(rawOpcode);

            if (!executeOpcode(static_cast<VMOpcode>(opcode))) {
                return false;
            }
        }

        return !state.stack.empty() && state.stack.back() != 0;
    }

private:
    bool executeOpcode(VMOpcode op) {
        switch (op) {
            case OP_PUSH_IMM8: {
                if (state.ip >= bytecode.size()) return false;
                state.stack.push_back(bytecode[state.ip++]);
                break;
            }

            case OP_PUSH_IMM32: {
                if (state.ip + 3 >= bytecode.size()) return false;
                int32_t value;
                std::memcpy(&value, &bytecode[state.ip], sizeof(value));
                state.ip += 4;
                state.stack.push_back(value);
                break;
            }

            case OP_PUSH_STR: {
                if (state.ip >= bytecode.size()) return false;
                uint8_t strIdx = bytecode[state.ip++];
                if (strIdx >= stringPool.size()) return false;
                state.stringStack.push_back(stringPool[strIdx]);
                break;
            }

            case OP_POP: {
                if (state.stack.empty()) return false;
                state.stack.pop_back();
                break;
            }

            case OP_DUP: {
                if (state.stack.empty()) return false;
                state.stack.push_back(state.stack.back());
                break;
            }

            case OP_FILE_OPEN: {
                if (state.stringStack.empty()) return false;
                std::string filename = state.stringStack.back();
                state.stringStack.pop_back();

                FILE* fp = fopen(filename.c_str(), "r");
                if (fp) {
                    uint8_t handle = state.nextFileHandle++;
                    state.fileHandles[handle] = fp;
                    state.stack.push_back(handle);
                } else {
                    state.stack.push_back(0);
                }
                break;
            }

            case OP_FILE_CLOSE: {
                if (state.stack.empty()) return false;
                uint8_t handle = static_cast<uint8_t>(state.stack.back());
                state.stack.pop_back();

                auto it = state.fileHandles.find(handle);
                if (it != state.fileHandles.end()) {
                    if (it->second) fclose(it->second);
                    state.fileHandles.erase(it);
                }
                break;
            }

            case OP_FILE_READ_LINE: {
                if (state.stack.empty()) return false;
                uint8_t handle = static_cast<uint8_t>(state.stack.back());
                state.stack.pop_back();

                auto it = state.fileHandles.find(handle);
                if (it == state.fileHandles.end() || !it->second) {
                    state.stringStack.emplace_back("");
                    state.stack.push_back(0);
                    break;
                }

                char line[2048];
                if (fgets(line, sizeof(line), it->second)) {
                    state.stringStack.emplace_back(line);
                    state.stack.push_back(1);
                } else {
                    state.stringStack.emplace_back("");
                    state.stack.push_back(0);
                }
                break;
            }

            case OP_FILE_EXISTS: {
                if (state.stringStack.empty()) return false;
                std::string path = state.stringStack.back();
                state.stringStack.pop_back();

                state.stack.push_back(access(path.c_str(), F_OK) == 0 ? 1 : 0);
                break;
            }

            case OP_STR_CONTAINS: {
                if (state.stringStack.size() < 2) return false;
                std::string substring = state.stringStack.back();
                state.stringStack.pop_back();
                std::string str = state.stringStack.back();
                state.stringStack.pop_back();

                state.stack.push_back(str.find(substring) != std::string::npos ? 1 : 0);
                break;
            }

            case OP_STR_COMPARE: {
                if (state.stringStack.size() < 2) return false;
                std::string str2 = state.stringStack.back();
                state.stringStack.pop_back();
                std::string str1 = state.stringStack.back();
                state.stringStack.pop_back();

                state.stack.push_back(str1 == str2 ? 1 : 0);
                break;
            }

            case OP_SYS_PROP_GET: {
                if (state.stringStack.empty()) return false;
                std::string propName = state.stringStack.back();
                state.stringStack.pop_back();

                char value[PROP_VALUE_MAX] = {0};
                __system_property_get(propName.c_str(), value);
                state.stringStack.emplace_back(value);
                break;
            }

            case OP_SYS_GETENV: {
                if (state.stringStack.empty()) return false;
                std::string varName = state.stringStack.back();
                state.stringStack.pop_back();

                const char* value = getenv(varName.c_str());
                state.stringStack.emplace_back(value ? value : "");
                break;
            }

            case OP_CMP_EQ: {
                if (state.stack.size() < 2) return false;
                int64_t b = state.stack.back(); state.stack.pop_back();
                int64_t a = state.stack.back(); state.stack.pop_back();
                state.stack.push_back(a == b ? 1 : 0);
                break;
            }

            case OP_CMP_NEQ: {
                if (state.stack.size() < 2) return false;
                int64_t b = state.stack.back(); state.stack.pop_back();
                int64_t a = state.stack.back(); state.stack.pop_back();
                state.stack.push_back(a != b ? 1 : 0);
                break;
            }

            case OP_JUMP_IF_TRUE: {
                if (state.stack.empty() || state.ip >= bytecode.size()) return false;
                int64_t condition = state.stack.back();
                state.stack.pop_back();
                int8_t offset = static_cast<int8_t>(bytecode[state.ip++]);

                if (condition != 0) {
                    state.ip = static_cast<size_t>(static_cast<int>(state.ip) + offset);
                }
                break;
            }

            case OP_JUMP_IF_FALSE: {
                if (state.stack.empty() || state.ip >= bytecode.size()) return false;
                int64_t condition = state.stack.back();
                state.stack.pop_back();
                int8_t offset = static_cast<int8_t>(bytecode[state.ip++]);

                if (condition == 0) {
                    state.ip = static_cast<size_t>(static_cast<int>(state.ip) + offset);
                }
                break;
            }

            case OP_OR: {
                if (state.stack.size() < 2) return false;
                int64_t b = state.stack.back(); state.stack.pop_back();
                int64_t a = state.stack.back(); state.stack.pop_back();
                state.stack.push_back((a != 0 || b != 0) ? 1 : 0);
                break;
            }

            case OP_AND: {
                if (state.stack.size() < 2) return false;
                int64_t b = state.stack.back(); state.stack.pop_back();
                int64_t a = state.stack.back(); state.stack.pop_back();
                state.stack.push_back((a != 0 && b != 0) ? 1 : 0);
                break;
            }

            case OP_NOT: {
                if (state.stack.empty()) return false;
                int64_t a = state.stack.back(); state.stack.pop_back();
                state.stack.push_back(a == 0 ? 1 : 0);
                break;
            }

            case OP_HALT: {
                state.halted = true;
                break;
            }

            case OP_NOP: {
                break;
            }

            case OP_DEBUG_CHECK: {
                ScopedFile f("/proc/self/status", "r");
                if (f.isOpen()) {
                    char line[256];
                    while (fgets(line, sizeof(line), f)) {
                        if (strncmp(line, "TracerPid:", 10) == 0) {
                            int tracer = atoi(line + 10);
                            if (tracer != 0) {
                                state.stack.push_back(0);
                                state.halted = true;
                                return true;
                            }
                        }
                    }
                }
                break;
            }

            default:
                return false;
        }

        return true;
    }
};

static uint8_t encodeOpcode(VMOpcode op) {
    return static_cast<uint8_t>(op) ^ VM_OBFUSCATION_KEY;
}

static std::pair<std::vector<uint8_t>, std::vector<std::string>> compileZygiskDetection() {
    std::vector<uint8_t> bytecode;
    std::vector<std::string> strings;

    strings.push_back("/proc/self/maps");      // 0
    strings.push_back("libzygisk.so");          // 1
    strings.push_back("libmagiskhide.so");      // 2
    strings.push_back("lspd");                  // 3
    strings.push_back("LSPosed");               // 4
    strings.push_back("[anon:zygisk]");         // 5
    strings.push_back("ZYGISK_ENABLED");        // 6
    strings.push_back("MAGISK_VER_CODE");       // 7

    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(6);
    bytecode.push_back(encodeOpcode(OP_SYS_GETENV));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(7);
    bytecode.push_back(encodeOpcode(OP_SYS_GETENV));
    bytecode.push_back(encodeOpcode(OP_OR));

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(60);

    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_FILE_OPEN));
    bytecode.push_back(encodeOpcode(OP_DUP));

    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_CMP_EQ));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(50);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_FILE_READ_LINE));

    bytecode.push_back(encodeOpcode(OP_JUMP_IF_FALSE));
    bytecode.push_back(30);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(20);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(2);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(15);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(3);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(10);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(4);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(5);

    bytecode.push_back(encodeOpcode(OP_POP));

    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(static_cast<uint8_t>(-40));

    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_HALT));

    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_HALT));

    return {bytecode, strings};
}

static std::pair<std::vector<uint8_t>, std::vector<std::string>> compilePIFDetection() {
    std::vector<uint8_t> bytecode;
    std::vector<std::string> strings;

    strings.push_back("/proc/self/maps");                           // 0
    strings.push_back("es.chiteroman.playintegrityfix");           // 1
    strings.push_back("CustomKeyStoreSpi");                         // 2
    strings.push_back("CustomProvider");                            // 3
    strings.push_back("PlayIntegrityFix");                         // 4
    strings.push_back("playintegrityfix");                         // 5

    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_FILE_OPEN));
    bytecode.push_back(encodeOpcode(OP_DUP));

    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_CMP_EQ));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(45);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_FILE_READ_LINE));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_FALSE));
    bytecode.push_back(35);

    for (int i = 1; i <= 5; i++) {
        bytecode.push_back(encodeOpcode(OP_DUP));
        bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(i);
        bytecode.push_back(encodeOpcode(OP_STR_CONTAINS));
        bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
        bytecode.push_back(20);
    }

    bytecode.push_back(encodeOpcode(OP_POP));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(static_cast<uint8_t>(-30));

    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_HALT));

    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_HALT));

    return {bytecode, strings};
}

static std::pair<std::vector<uint8_t>, std::vector<std::string>> compileFridaDetection() {
    std::vector<uint8_t> bytecode;
    std::vector<std::string> strings;

    strings.push_back("/proc/net/unix");   // 0
    strings.push_back("frida");            // 1
    strings.push_back("xposed");           // 2
    strings.push_back("re.frida");         // 3

    bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_FILE_OPEN));
    bytecode.push_back(encodeOpcode(OP_DUP));

    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_CMP_EQ));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(40);

    bytecode.push_back(encodeOpcode(OP_DUP));
    bytecode.push_back(encodeOpcode(OP_FILE_READ_LINE));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_FALSE));
    bytecode.push_back(30);

    for (int i = 1; i <= 3; i++) {
        bytecode.push_back(encodeOpcode(OP_DUP));
        bytecode.push_back(encodeOpcode(OP_PUSH_STR)); bytecode.push_back(i);
        bytecode.push_back(encodeOpcode(OP_STR_CONTAINS));
        bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
        bytecode.push_back(15);
    }

    bytecode.push_back(encodeOpcode(OP_POP));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE));
    bytecode.push_back(static_cast<uint8_t>(-25));

    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_HALT));

    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_HALT));

    return {bytecode, strings};
}

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
        }
        maps.close();
    }

    char prop[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.magisk.zygisk", prop);
    return strlen(prop) > 0 && strcmp(prop, "0") != 0;
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
                line.find(Deobfuscate(base64_decode("QDQlOCUnRD0jMyU9ST4tOQ=="))) != std::string::npos) {
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

    return bootloader.find("unlock") != std::string::npos ||
           (!verified_boot_state.empty() && verified_boot_state != "green") ||
           veritymode == "disabled" ||
           flash_locked == "0";
}

static bool isAppDebuggable(JNIEnv *env, jobject context) {
    jclass contextClass = env->FindClass("android/content/Context");
    if (!contextClass) return false;

    jmethodID getAppInfo = env->GetMethodID(contextClass, "getApplicationInfo",
        "()Landroid/content/pm/ApplicationInfo;");
    if (!getAppInfo) return false;

    jobject appInfo = env->CallObjectMethod(context, getAppInfo);
    if (!appInfo) return false;

    jclass appInfoClass = env->FindClass("android/content/pm/ApplicationInfo");
    if (!appInfoClass) return false;

    jfieldID flagsField = env->GetFieldID(appInfoClass, "flags", "I");
    if (!flagsField) return false;

    jint flags = env->GetIntField(appInfo, flagsField);

    env->DeleteLocalRef(appInfo);
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(appInfoClass);

    return (flags & 0x2) != 0;
}

static bool verifyAPKSignature(JNIEnv *env, jobject context) {
    jclass contextClass = env->FindClass("android/content/Context");
    if (!contextClass) return true;

    jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName",
        "()Ljava/lang/String;");
    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager",
        "()Landroid/content/pm/PackageManager;");
    if (!getPackageName || !getPackageManager) return true;

    jstring packageName = (jstring)env->CallObjectMethod(context, getPackageName);
    jobject pm = env->CallObjectMethod(context, getPackageManager);
    if (!packageName || !pm) return true;

    jclass pmClass = env->FindClass("android/content/pm/PackageManager");
    if (!pmClass) return true;

    jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPackageInfo) return true;

    jobject packageInfo = env->CallObjectMethod(pm, getPackageInfo, packageName, 0x40);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    if (!packageInfo) return true;

    jclass piClass = env->FindClass("android/content/pm/PackageInfo");
    if (!piClass) return true;

    jfieldID sigField = env->GetFieldID(piClass, "signatures",
        "[Landroid/content/pm/Signature;");
    if (!sigField) return true;

    jobjectArray signatures = (jobjectArray)env->GetObjectField(packageInfo, sigField);
    if (!signatures || env->GetArrayLength(signatures) == 0) return false;

    jobject sig = env->GetObjectArrayElement(signatures, 0);
    if (!sig) return false;

    jclass sigClass = env->FindClass("android/content/pm/Signature");
    jmethodID hashCodeMethod = env->GetMethodID(sigClass, "hashCode", "()I");
    if (!hashCodeMethod) return true;

    jint sigHash = env->CallIntMethod(sig, hashCodeMethod);

    // update when switching signing keys
    static constexpr jint EXPECTED_SIG_HASH = 310268329;
    return sigHash == EXPECTED_SIG_HASH;
}

extern "C"
JNIEXPORT jint JNICALL
f5d6d8a0228d2e7b607f28fefe95c77(JNIEnv *env, jobject obj) {
    if (isTraced() == 1)
        return -1;

    auto [fridaBytecode, fridaStrings] = compileFridaDetection();
    SecureVM fridaVM(fridaBytecode, fridaStrings);
    if (fridaVM.execute())
        return -1;

    if (detectSuspiciousParent() == 1)
        return -1;

    if (isAppDebuggable(env, obj))
        return -1;

    auto [zygiskBytecode, zygiskStrings] = compileZygiskDetection();
    SecureVM zygiskVM(zygiskBytecode, zygiskStrings);
    bool zygiskDetected = zygiskVM.execute() || isZygiskActiveEnhanced();

    auto [pifBytecode, pifStrings] = compilePIFDetection();
    SecureVM pifVM(pifBytecode, pifStrings);
    bool pifDetected = pifVM.execute() || detectPIFSideEffects();

    if (zygiskDetected || pifDetected || isBootloaderUnlocked() || !verifyAPKSignature(env, obj))
        return 1;

    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    static const std::string className = Deobfuscate(base64_decode(
        "UzcpbikxUTU0LSlmQDQlOAUnRD0jMyU9SR4tOQgsRD0nNSM7HxUlKCIIUywtNyU9SQ=="));
    static const std::string methodName = Deobfuscate(base64_decode(
        "WSsNLzgsVyotNTUdUTU0JD4sVA=="));

    jclass clazz = env->FindClass(className.c_str());
    if (!clazz)
        return JNI_ERR;

    static const JNINativeMethod methods[] = {
        {const_cast<char*>(methodName.c_str()),
         const_cast<char*>("()I"),
         reinterpret_cast<void *>(f5d6d8a0228d2e7b607f28fefe95c77)}
    };

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) < 0)
        return JNI_ERR;

    return JNI_VERSION_1_6;
}
