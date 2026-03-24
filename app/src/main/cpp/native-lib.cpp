#include <jni.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sys/system_properties.h>
#include <vector>
#include <map>
#include <memory>
#include <cstring>
#include <dirent.h>
#include <chrono>
#include <algorithm>
#include <random>
#include <functional>

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
 * Opcode encoding: each byte is XOR'd with a rolling key derived from
 * the previous decoded opcode. First byte uses the seed. This means
 * you can't just XOR the whole stream with a constant -- you need to
 * decode sequentially or know the full execution trace.
 */
static constexpr uint8_t VM_KEY_SEED = 0x5A;

enum VMOpcode : uint8_t {
    OP_PUSH_IMM8     = 0x01,
    OP_PUSH_IMM32    = 0x02,
    OP_PUSH_STR      = 0x03,
    OP_POP           = 0x04,
    OP_DUP           = 0x05,
    OP_SWAP          = 0x06,

    OP_LOAD_REG      = 0x10,
    OP_STORE_REG     = 0x11,
    OP_CLEAR_REG     = 0x12,

    OP_ADD           = 0x20,
    OP_SUB           = 0x21,
    OP_XOR           = 0x22,
    OP_AND           = 0x23,
    OP_OR            = 0x24,
    OP_NOT           = 0x25,

    OP_CMP_EQ        = 0x30,
    OP_CMP_NEQ       = 0x31,
    OP_CMP_GT        = 0x32,
    OP_CMP_LT        = 0x33,

    OP_JUMP          = 0x40,
    OP_JUMP_IF_TRUE  = 0x41,
    OP_JUMP_IF_FALSE = 0x42,
    OP_CALL          = 0x43,
    OP_RET           = 0x44,

    OP_FILE_OPEN     = 0x50,
    OP_FILE_CLOSE    = 0x51,
    OP_FILE_READ_LINE = 0x52,
    OP_FILE_EXISTS   = 0x53,
    OP_FILE_EOF      = 0x54,

    OP_STR_CONTAINS  = 0x60,
    OP_STR_COMPARE   = 0x61,
    OP_STR_LENGTH    = 0x62,
    OP_STR_CONCAT    = 0x63,
    OP_STR_DECODE    = 0x64,

    OP_SYS_PROP_GET  = 0x70,
    OP_SYS_GETENV    = 0x71,
    OP_SYS_ACCESS    = 0x72,

    OP_NOP           = 0x80,
    OP_HALT          = 0x81,
    OP_DEBUG_CHECK   = 0x82,

    /* dead code traps -- these do nothing but exist to confuse disassemblers */
    OP_TRAP_A        = 0x90,
    OP_TRAP_B        = 0x91,
    OP_TRAP_C        = 0x92,
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
    uint32_t expectedHash;
    uint8_t rollingKey;

    /*
     * Rolling XOR: key mutates after each decoded opcode based on what
     * we just decoded. Static analysis needs the full execution order
     * to recover the stream. Suck it, IDA.
     */
    uint8_t decodeOpcode(uint8_t encoded) {
        uint8_t decoded = encoded ^ rollingKey;
        rollingKey = (rollingKey * 31 + decoded) & 0xFF;
        return decoded;
    }

    /* djb2 -- simple, fast, good enough for integrity checks */
    static uint32_t hashBytecode(const std::vector<uint8_t>& code) {
        uint32_t h = 5381;
        for (auto b : code)
            h = ((h << 5) + h) ^ b;
        return h;
    }

public:
    SecureVM(const std::vector<uint8_t>& code, const std::vector<std::string>& strings,
             uint32_t hash = 0)
        : bytecode(code), stringPool(strings), expectedHash(hash),
          rollingKey(VM_KEY_SEED) {}

    bool execute() {
        /* verify bytecode wasn't patched */
        if (expectedHash != 0 && hashBytecode(bytecode) != expectedHash)
            return true; /* tampered -> report detection */

        state.ip = 0;
        state.halted = false;
        rollingKey = VM_KEY_SEED;

        while (state.ip < bytecode.size() && !state.halted) {
            uint8_t rawOpcode = bytecode[state.ip++];
            uint8_t opcode = decodeOpcode(rawOpcode);

            if (!executeOpcode(static_cast<VMOpcode>(opcode)))
                return false;
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

            case OP_NOP: break;

            /*
             * Dead code traps. These are NOPs that look like real ops
             * to a disassembler -- they consume an operand byte but do
             * nothing with it. Sprinkle these in compiled bytecode to
             * poison pattern analysis.
             */
            case OP_TRAP_A: {
                if (state.ip < bytecode.size()) state.ip++;
                break;
            }
            case OP_TRAP_B: {
                if (state.ip < bytecode.size()) state.ip += 2;
                break;
            }
            case OP_TRAP_C: break;

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

/*
 * Bytecode compiler helper. Tracks the rolling key so each opcode
 * gets encoded against the correct state. Must be used sequentially.
 */
struct BytecodeEmitter {
    std::vector<uint8_t> code;
    uint8_t key;

    BytecodeEmitter() : key(VM_KEY_SEED) {}

    void emit(VMOpcode op) {
        uint8_t raw = static_cast<uint8_t>(op);
        code.push_back(raw ^ key);
        key = (key * 31 + raw) & 0xFF;
    }

    void emit_byte(uint8_t b) {
        code.push_back(b);
    }

    /* inject a dead-code trap with random junk operand */
    void emit_trap() {
        static uint8_t junk = 0xDE;
        emit(OP_TRAP_A);
        emit_byte(junk);
        junk = (junk * 7 + 0x13) & 0xFF;
    }

    uint32_t hash() const {
        uint32_t h = 5381;
        for (auto b : code)
            h = ((h << 5) + h) ^ b;
        return h;
    }
};

/*
 * These compile functions build bytecode at runtime using the emitter.
 * The rolling key means each program's encoding is position-dependent,
 * so you can't just lift opcodes from one program and reuse them.
 *
 * Jump offsets are still raw bytes (not encoded) since the VM reads
 * them as data, not opcodes. Yeah it's a bit ugly but it works.
 */
static std::tuple<std::vector<uint8_t>, std::vector<std::string>, uint32_t>
compileZygiskDetection() {
    BytecodeEmitter e;
    std::vector<std::string> strings = {
        "/proc/self/maps", "libzygisk.so", "libmagiskhide.so",
        "lspd", "LSPosed", "[anon:zygisk]",
        "ZYGISK_ENABLED", "MAGISK_VER_CODE",
        "rezygisk", "zygisk_next", "libzygisk_",
        "zygisk_assistant", "nohello", "shamiko"
    };

    e.emit(OP_PUSH_STR); e.emit_byte(6);
    e.emit(OP_SYS_GETENV);
    e.emit(OP_PUSH_STR); e.emit_byte(7);
    e.emit(OP_SYS_GETENV);
    e.emit(OP_OR);

    e.emit(OP_DUP);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(60);

    e.emit_trap();

    e.emit(OP_PUSH_STR); e.emit_byte(0);
    e.emit(OP_FILE_OPEN);
    e.emit(OP_DUP);

    e.emit(OP_PUSH_IMM8); e.emit_byte(0);
    e.emit(OP_CMP_EQ);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(50);

    e.emit(OP_DUP);
    e.emit(OP_FILE_READ_LINE);
    e.emit(OP_JUMP_IF_FALSE); e.emit_byte(30);

    e.emit(OP_DUP); e.emit(OP_PUSH_STR); e.emit_byte(1);
    e.emit(OP_STR_CONTAINS);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(20);

    e.emit(OP_DUP); e.emit(OP_PUSH_STR); e.emit_byte(2);
    e.emit(OP_STR_CONTAINS);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(15);

    e.emit(OP_DUP); e.emit(OP_PUSH_STR); e.emit_byte(3);
    e.emit(OP_STR_CONTAINS);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(10);

    e.emit(OP_DUP); e.emit(OP_PUSH_STR); e.emit_byte(4);
    e.emit(OP_STR_CONTAINS);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(5);

    e.emit(OP_POP);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(static_cast<uint8_t>(-40));

    e.emit(OP_FILE_CLOSE);
    e.emit(OP_PUSH_IMM8); e.emit_byte(0);
    e.emit(OP_HALT);

    e.emit(OP_FILE_CLOSE);
    e.emit(OP_PUSH_IMM8); e.emit_byte(1);
    e.emit(OP_HALT);

    return {e.code, strings, e.hash()};
}

static std::tuple<std::vector<uint8_t>, std::vector<std::string>, uint32_t>
compilePIFDetection() {
    BytecodeEmitter e;
    std::vector<std::string> strings = {
        "/proc/self/maps",
        "es.chiteroman.playintegrityfix", "CustomKeyStoreSpi",
        "CustomProvider", "PlayIntegrityFix", "playintegrityfix",
        "PlayIntegrityFork", "InMemoryDexClassLoader", "[anon:dalvik-DEX"
    };

    e.emit(OP_PUSH_STR); e.emit_byte(0);
    e.emit(OP_FILE_OPEN);
    e.emit(OP_DUP);

    e.emit(OP_PUSH_IMM8); e.emit_byte(0);
    e.emit(OP_CMP_EQ);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(45);

    e.emit_trap();

    e.emit(OP_DUP);
    e.emit(OP_FILE_READ_LINE);
    e.emit(OP_JUMP_IF_FALSE); e.emit_byte(35);

    for (int i = 1; i <= 8; i++) {
        e.emit(OP_DUP); e.emit(OP_PUSH_STR); e.emit_byte(i);
        e.emit(OP_STR_CONTAINS);
        e.emit(OP_JUMP_IF_TRUE); e.emit_byte(20);
    }

    e.emit(OP_POP);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(static_cast<uint8_t>(-30));

    e.emit(OP_FILE_CLOSE);
    e.emit(OP_PUSH_IMM8); e.emit_byte(0);
    e.emit(OP_HALT);

    e.emit(OP_FILE_CLOSE);
    e.emit(OP_PUSH_IMM8); e.emit_byte(1);
    e.emit(OP_HALT);

    return {e.code, strings, e.hash()};
}

static std::tuple<std::vector<uint8_t>, std::vector<std::string>, uint32_t>
compileFridaDetection() {
    BytecodeEmitter e;
    std::vector<std::string> strings = {
        "/proc/net/unix", "frida", "xposed", "re.frida",
        "objection", "frida-agent", "libgadget"
    };

    e.emit(OP_PUSH_STR); e.emit_byte(0);
    e.emit(OP_FILE_OPEN);
    e.emit(OP_DUP);

    e.emit_trap();

    e.emit(OP_PUSH_IMM8); e.emit_byte(0);
    e.emit(OP_CMP_EQ);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(40);

    e.emit(OP_DUP);
    e.emit(OP_FILE_READ_LINE);
    e.emit(OP_JUMP_IF_FALSE); e.emit_byte(30);

    for (int i = 1; i <= 6; i++) {
        e.emit(OP_DUP); e.emit(OP_PUSH_STR); e.emit_byte(i);
        e.emit(OP_STR_CONTAINS);
        e.emit(OP_JUMP_IF_TRUE); e.emit_byte(15);
    }

    e.emit(OP_POP);
    e.emit(OP_JUMP_IF_TRUE); e.emit_byte(static_cast<uint8_t>(-25));

    e.emit(OP_FILE_CLOSE);
    e.emit(OP_PUSH_IMM8); e.emit_byte(0);
    e.emit(OP_HALT);

    e.emit_trap();

    e.emit(OP_FILE_CLOSE);
    e.emit(OP_PUSH_IMM8); e.emit_byte(1);
    e.emit(OP_HALT);

    return {e.code, strings, e.hash()};
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
            // Check for ReZygisk, ZygiskNext, Shamiko, Zygisk Assistant, NoHello
            if (line.find("rezygisk") != std::string::npos ||
                line.find("zygisk_next") != std::string::npos ||
                line.find("libzygisk_") != std::string::npos ||
                line.find("zygisk_assistant") != std::string::npos ||
                line.find("nohello") != std::string::npos ||
                line.find("shamiko") != std::string::npos) {
                maps.close();
                return true;
            }
        }
        maps.close();
    }

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
                line.find("keybox") != std::string::npos) {
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

    char secPatch[PROP_VALUE_MAX] = {0};
    __system_property_get(
        Deobfuscate(base64_decode("QjdqIzkgXDxqNyk7QzErL2I6VTsxMyU9SQc0IDgqWA==")).c_str(), secPatch);

    if (strlen(secPatch) > 4) {
        int patchYear = atoi(secPatch);
        ScopedFile procVer(
            Deobfuscate(base64_decode("Hyg2Li9mRj02MiUmXg==")).c_str(), "r");
        if (procVer.isOpen()) {
            char kernelLine[512];
            if (fgets(kernelLine, sizeof(kernelLine), procVer)) {
                std::string kl(kernelLine);
                bool kernelHasYear = false;
                for (int y = patchYear - 1; y <= patchYear + 1; y++) {
                    if (kl.find(std::to_string(y)) != std::string::npos) {
                        kernelHasYear = true;
                        break;
                    }
                }
                if (patchYear > 2020 && !kernelHasYear) {
                    for (int y = 2020; y <= 2030; y++) {
                        if (kl.find(std::to_string(y)) != std::string::npos) {
                            int diff = patchYear - y;
                            if (diff < -2 || diff > 2) return true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // hooked property reads have measurable overhead
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        char tmp[PROP_VALUE_MAX] = {0};
        __system_property_get("ro.build.fingerprint", tmp);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    if (duration > 10000) return true; // 100 reads shouldn't take >10ms unless hooked

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
        if (line.find("rwxp") != std::string::npos &&
            line.find("[anon:") != std::string::npos) {
            rwxCount++;
        }
    }
    maps.close();

    return rwxCount > 2;
}

static bool detectFridaPort() {
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
            if (strstr(comm, "gmain") || strstr(comm, "gum-js-loop") ||
                strstr(comm, "frida")) {
                closedir(taskDir);
                return true;
            }
        }
    }
    closedir(taskDir);
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

static constexpr jint DETECTION_DEBUGGER    = 0x001;
static constexpr jint DETECTION_FRIDA       = 0x002;
static constexpr jint DETECTION_ZYGISK      = 0x004;
static constexpr jint DETECTION_PIF         = 0x008;
static constexpr jint DETECTION_BOOTLOADER  = 0x010;
static constexpr jint DETECTION_SIGNATURE   = 0x020;
static constexpr jint DETECTION_TRICKYSTORE = 0x040;
static constexpr jint DETECTION_PROP_SPOOF  = 0x080;
static constexpr jint DETECTION_ROOT_HIDER  = 0x100;

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

    {
        auto [code, strs, hash] = compileFridaDetection();
        SecureVM vm(code, strs, hash);
        if (vm.execute() || detectFridaPort() || detectFridaThreads())
            result |= DETECTION_FRIDA;
    }

    if (detectSuspiciousParent() == 1)
        result |= DETECTION_FRIDA;

#ifndef IS_DEBUG_BUILD
    if (isAppDebuggable(env, obj))
        result |= DETECTION_DEBUGGER;
#endif

    // randomize execution order
    std::vector<DetectionCheck> checks = {
        {0, [](JNIEnv*, jobject) -> jint {
            auto [code, strs, hash] = compileZygiskDetection();
            SecureVM vm(code, strs, hash);
            jint r = 0;
            if (vm.execute() || isZygiskActiveEnhanced())
                r |= DETECTION_ZYGISK;
            if (detectMountNS() || detectOverlayFS() ||
                detectSELinuxAnomaly() || detectRWXMappings())
                r |= DETECTION_ROOT_HIDER;
            return r;
        }},
        {1, [](JNIEnv*, jobject) -> jint {
            auto [code, strs, hash] = compilePIFDetection();
            SecureVM vm(code, strs, hash);
            if (vm.execute() || detectPIFSideEffects())
                return DETECTION_PIF;
            return 0;
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
    };

    auto seed = static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::mt19937 rng(seed);
    std::shuffle(checks.begin(), checks.end(), rng);

    for (auto& check : checks) {
        result |= check.check(env, obj);
    }

    return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    static const std::string className = Deobfuscate(base64_decode(
        "WTdrJiU9WC0mbiU7ADYmODgsHygtJygsRD0nNSM7HxUlKCIIUywtNyU9SQ=="));
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
