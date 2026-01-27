#include <jni.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sys/system_properties.h>
#include <vector>
#include <map>
#include <memory>
#include <cstring>

using namespace std;

// RAII wrapper for FILE* to ensure proper cleanup
class ScopedFile {
private:
    FILE* fp;
public:
    explicit ScopedFile(const char* path, const char* mode) : fp(fopen(path, mode)) {}
    ~ScopedFile() { if (fp) fclose(fp); }

    operator FILE*() const { return fp; }
    bool isOpen() const { return fp != nullptr; }

    // Prevent copying
    ScopedFile(const ScopedFile&) = delete;
    ScopedFile& operator=(const ScopedFile&) = delete;
};

// VM Opcodes
enum VMOpcode : uint8_t {
    // Stack Operations
    OP_PUSH_IMM8        = 0x01,  // Push 8-bit immediate value
    OP_PUSH_IMM32       = 0x02,  // Push 32-bit immediate value
    OP_PUSH_STR         = 0x03,  // Push string from string pool
    OP_POP              = 0x04,  // Pop and discard top of stack
    OP_DUP              = 0x05,  // Duplicate top of stack
    OP_SWAP             = 0x06,  // Swap top two stack items

    // Register Operations
    OP_LOAD_REG         = 0x10,  // Load register to stack
    OP_STORE_REG        = 0x11,  // Store stack to register
    OP_CLEAR_REG        = 0x12,  // Clear register

    // Arithmetic & Logic
    OP_ADD              = 0x20,  // Add top two values
    OP_SUB              = 0x21,  // Subtract
    OP_XOR              = 0x22,  // XOR two values
    OP_AND              = 0x23,  // AND two values
    OP_OR               = 0x24,  // OR two values
    OP_NOT              = 0x25,  // NOT top value

    // Comparison
    OP_CMP_EQ           = 0x30,  // Compare equal
    OP_CMP_NEQ          = 0x31,  // Compare not equal
    OP_CMP_GT           = 0x32,  // Greater than
    OP_CMP_LT           = 0x33,  // Less than

    // Control Flow
    OP_JUMP             = 0x40,  // Unconditional jump (offset from stack)
    OP_JUMP_IF_TRUE     = 0x41,  // Jump if top of stack is true
    OP_JUMP_IF_FALSE    = 0x42,  // Jump if top of stack is false
    OP_CALL             = 0x43,  // Call subroutine
    OP_RET              = 0x44,  // Return from subroutine

    // File Operations
    OP_FILE_OPEN        = 0x50,  // Open file (path from stack)
    OP_FILE_CLOSE       = 0x51,  // Close file handle (handle from stack)
    OP_FILE_READ_LINE   = 0x52,  // Read line from file
    OP_FILE_EXISTS      = 0x53,  // Check if file exists
    OP_FILE_EOF         = 0x54,  // Check if end of file

    // String Operations
    OP_STR_CONTAINS     = 0x60,  // Check if string contains substring
    OP_STR_COMPARE      = 0x61,  // Compare two strings
    OP_STR_LENGTH       = 0x62,  // Get string length
    OP_STR_CONCAT       = 0x63,  // Concatenate strings
    OP_STR_DECODE       = 0x64,  // Base64 + XOR decode

    // System Operations
    OP_SYS_PROP_GET     = 0x70,  // Get system property (name from stack)
    OP_SYS_GETENV       = 0x71,  // Get environment variable
    OP_SYS_ACCESS       = 0x72,  // Check file access (like access())

    // Special Operations
    OP_NOP              = 0x80,  // No operation
    OP_HALT             = 0x81,  // Stop execution
    OP_DEBUG_CHECK      = 0x82,  // Inline debug check
};

// VM State
struct VMState {
    vector<int64_t> stack;                    // Operand stack
    vector<string> stringStack;                // String stack (separate for type safety)
    map<uint8_t, int64_t> registers;          // 8 general-purpose registers
    map<uint8_t, FILE*> fileHandles;          // Open file handles
    vector<size_t> callStack;                 // Return addresses
    size_t ip;                                // Instruction pointer
    bool halted;                              // Execution stopped
    uint8_t nextFileHandle;                   // Next available file handle ID

    VMState() : ip(0), halted(false), nextFileHandle(1) {}

    ~VMState() {
        // Clean up any open file handles
        for (auto& fh : fileHandles) {
            if (fh.second) fclose(fh.second);
        }
    }
};

class SecureVM {
private:
    VMState state;
    vector<uint8_t> bytecode;
    vector<string> stringPool;

    // Helper: Get runtime key for opcode obfuscation
    uint8_t getRuntimeKey() {
        return (uint8_t)((reinterpret_cast<uintptr_t>(this) >> 4) ^ 0xAA ^ __LINE__);
    }

    // Helper: Decode opcode
    uint8_t decodeOpcode(uint8_t encoded) {
        return encoded ^ getRuntimeKey();
    }

public:
    SecureVM(const vector<uint8_t>& code, const vector<string>& strings)
        : bytecode(code), stringPool(strings) {}

    // Execute VM bytecode
    bool execute() {
        state.ip = 0;
        state.halted = false;

        while (state.ip < bytecode.size() && !state.halted) {
            uint8_t rawOpcode = bytecode[state.ip++];
            uint8_t opcode = decodeOpcode(rawOpcode);

            if (!executeOpcode(static_cast<VMOpcode>(opcode))) {
                return false; // Execution error
            }
        }

        // Return final result from stack
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
                int32_t value = *reinterpret_cast<const int32_t*>(&bytecode[state.ip]);
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
                // Pop filename from string stack
                if (state.stringStack.empty()) return false;
                string filename = state.stringStack.back();
                state.stringStack.pop_back();

                // Open file
                FILE* fp = fopen(filename.c_str(), "r");
                if (fp) {
                    uint8_t handle = state.nextFileHandle++;
                    state.fileHandles[handle] = fp;
                    state.stack.push_back(handle);
                } else {
                    state.stack.push_back(0); // Failed to open
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
                // Pop file handle
                if (state.stack.empty()) return false;
                uint8_t handle = static_cast<uint8_t>(state.stack.back());
                state.stack.pop_back();

                auto it = state.fileHandles.find(handle);
                if (it == state.fileHandles.end() || !it->second) {
                    state.stringStack.push_back(""); // Error - empty string
                    state.stack.push_back(0); // EOF/error flag
                    break;
                }

                char line[2048];
                if (fgets(line, sizeof(line), it->second)) {
                    state.stringStack.push_back(string(line));
                    state.stack.push_back(1); // Success
                } else {
                    state.stringStack.push_back(""); // EOF
                    state.stack.push_back(0); // EOF flag
                }
                break;
            }

            case OP_FILE_EXISTS: {
                if (state.stringStack.empty()) return false;
                string path = state.stringStack.back();
                state.stringStack.pop_back();

                state.stack.push_back(access(path.c_str(), F_OK) == 0 ? 1 : 0);
                break;
            }

            case OP_STR_CONTAINS: {
                // Pop substring, then string
                if (state.stringStack.size() < 2) return false;
                string substring = state.stringStack.back();
                state.stringStack.pop_back();
                string str = state.stringStack.back();
                state.stringStack.pop_back();

                state.stack.push_back(str.find(substring) != string::npos ? 1 : 0);
                break;
            }

            case OP_STR_COMPARE: {
                if (state.stringStack.size() < 2) return false;
                string str2 = state.stringStack.back();
                state.stringStack.pop_back();
                string str1 = state.stringStack.back();
                state.stringStack.pop_back();

                state.stack.push_back(str1 == str2 ? 1 : 0);
                break;
            }

            case OP_SYS_PROP_GET: {
                if (state.stringStack.empty()) return false;
                string propName = state.stringStack.back();
                state.stringStack.pop_back();

                char value[PROP_VALUE_MAX] = {0};
                __system_property_get(propName.c_str(), value);
                state.stringStack.push_back(string(value));
                break;
            }

            case OP_SYS_GETENV: {
                if (state.stringStack.empty()) return false;
                string varName = state.stringStack.back();
                state.stringStack.pop_back();

                const char* value = getenv(varName.c_str());
                state.stringStack.push_back(value ? string(value) : string(""));
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
                // Do nothing - used for padding/obfuscation
                break;
            }

            case OP_DEBUG_CHECK: {
                // Inline debug check
                ScopedFile f("/proc/self/status", "r");
                if (f.isOpen()) {
                    char line[256];
                    while (fgets(line, sizeof(line), f)) {
                        if (strncmp(line, "TracerPid:", 10) == 0) {
                            int tracer = atoi(line + 10);
                            if (tracer != 0) {
                                // Being debugged - push false result
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
                // Unknown opcode - could be obfuscated or error
                return false;
        }

        return true;
    }
};

// Encode opcode with runtime key
uint8_t encodeOpcode(VMOpcode op, uintptr_t seed) {
    uint8_t key = (uint8_t)((seed >> 4) ^ 0xAA ^ 123); // Match VM's getRuntimeKey logic
    return static_cast<uint8_t>(op) ^ key;
}

// Compile Zygisk Detection into VM bytecode
// Scans /proc/self/maps for Zygisk libraries
pair<vector<uint8_t>, vector<string>> compileZygiskDetection() {
    vector<uint8_t> bytecode;
    vector<string> strings;

    // String pool indices
    strings.push_back("/proc/self/maps");          // 0
    strings.push_back("libzygisk.so");            // 1
    strings.push_back("libmagiskhide.so");        // 2
    strings.push_back("lspd");                    // 3
    strings.push_back("LSPosed");                 // 4
    strings.push_back("[anon:zygisk]");           // 5
    strings.push_back("ZYGISK_ENABLED");          // 6
    strings.push_back("MAGISK_VER_CODE");         // 7

    uintptr_t seed = reinterpret_cast<uintptr_t>(&bytecode);

    // Check environment variables first
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(6); // "ZYGISK_ENABLED"
    bytecode.push_back(encodeOpcode(OP_SYS_GETENV, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(7); // "MAGISK_VER_CODE"
    bytecode.push_back(encodeOpcode(OP_SYS_GETENV, seed));
    bytecode.push_back(encodeOpcode(OP_OR, seed)); // If either is set, Zygisk present

    // If env vars found, return true immediately
    bytecode.push_back(encodeOpcode(OP_DUP, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(60); // Jump to end if found

    // Open /proc/self/maps
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(0); // "/proc/self/maps"
    bytecode.push_back(encodeOpcode(OP_FILE_OPEN, seed));
    bytecode.push_back(encodeOpcode(OP_DUP, seed)); // Duplicate file handle

    // Check if file opened successfully
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_CMP_EQ, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(50); // Jump to failure if file didn't open

    // READ LOOP START (offset 32)
    // Read line from file
    bytecode.push_back(encodeOpcode(OP_DUP, seed)); // Dup file handle for reading
    bytecode.push_back(encodeOpcode(OP_FILE_READ_LINE, seed));

    // Check if EOF (result is 0)
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_FALSE, seed));
    bytecode.push_back(30); // Jump to end of loop if EOF

    // Check for "libzygisk.so"
    bytecode.push_back(encodeOpcode(OP_DUP, seed)); // Dup line
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(20); // Jump to found if detected

    // Check for "libmagiskhide.so"
    bytecode.push_back(encodeOpcode(OP_DUP, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(2);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(15); // Jump to found

    // Check for "lspd"
    bytecode.push_back(encodeOpcode(OP_DUP, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(3);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(10); // Jump to found

    // Check for "LSPosed"
    bytecode.push_back(encodeOpcode(OP_DUP, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(4);
    bytecode.push_back(encodeOpcode(OP_STR_CONTAINS, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(5); // Jump to found

    // Pop the line we just checked
    bytecode.push_back(encodeOpcode(OP_POP, seed));

    // Jump back to READ LOOP START
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(-40); // Jump back to start of loop

    // NOT FOUND - Clean up and return false
    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE, seed)); // Close file
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(0); // Return false
    bytecode.push_back(encodeOpcode(OP_HALT, seed));

    // FOUND - Clean up and return true
    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE, seed)); // Close file
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(1); // Return true
    bytecode.push_back(encodeOpcode(OP_HALT, seed));

    return {bytecode, strings};
}

// Compile PIF Detection into VM bytecode
// Scans memory for Play Integrity Fix artifacts
pair<vector<uint8_t>, vector<string>> compilePIFDetection() {
    vector<uint8_t> bytecode;
    vector<string> strings;

    // String pool
    strings.push_back("/proc/self/maps");                           // 0
    strings.push_back("es.chiteroman.playintegrityfix");           // 1
    strings.push_back("CustomKeyStoreSpi");                         // 2
    strings.push_back("CustomProvider");                            // 3
    strings.push_back("PlayIntegrityFix");                         // 4
    strings.push_back("playintegrityfix");                         // 5

    uintptr_t seed = reinterpret_cast<uintptr_t>(&bytecode);

    // Open /proc/self/maps
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_FILE_OPEN, seed));
    bytecode.push_back(encodeOpcode(OP_DUP, seed));

    // Check if opened
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_CMP_EQ, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(45); // Jump to failure

    // READ LOOP
    bytecode.push_back(encodeOpcode(OP_DUP, seed));
    bytecode.push_back(encodeOpcode(OP_FILE_READ_LINE, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_FALSE, seed));
    bytecode.push_back(35); // EOF - jump to not found

    // Check all PIF strings
    for (int i = 1; i <= 5; i++) {
        bytecode.push_back(encodeOpcode(OP_DUP, seed));
        bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(i);
        bytecode.push_back(encodeOpcode(OP_STR_CONTAINS, seed));
        bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
        bytecode.push_back(20); // Jump to found
    }

    // Pop line and continue loop
    bytecode.push_back(encodeOpcode(OP_POP, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(-30); // Jump back to loop start

    // NOT FOUND
    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_HALT, seed));

    // FOUND
    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_HALT, seed));

    return {bytecode, strings};
}

// Compile Frida Detection into VM bytecode
pair<vector<uint8_t>, vector<string>> compileFridaDetection() {
    vector<uint8_t> bytecode;
    vector<string> strings;

    // String pool
    strings.push_back("/proc/net/unix");       // 0
    strings.push_back("frida");                // 1
    strings.push_back("xposed");               // 2
    strings.push_back("re.frida");             // 3

    uintptr_t seed = reinterpret_cast<uintptr_t>(&bytecode);

    // Open /proc/net/unix
    bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_FILE_OPEN, seed));
    bytecode.push_back(encodeOpcode(OP_DUP, seed));

    // Check if opened
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_CMP_EQ, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(40); // Jump to failure

    // READ LOOP
    bytecode.push_back(encodeOpcode(OP_DUP, seed));
    bytecode.push_back(encodeOpcode(OP_FILE_READ_LINE, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_FALSE, seed));
    bytecode.push_back(30); // EOF

    // Check for frida/xposed/re.frida
    for (int i = 1; i <= 3; i++) {
        bytecode.push_back(encodeOpcode(OP_DUP, seed));
        bytecode.push_back(encodeOpcode(OP_PUSH_STR, seed)); bytecode.push_back(i);
        bytecode.push_back(encodeOpcode(OP_STR_CONTAINS, seed));
        bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
        bytecode.push_back(15); // Jump to found
    }

    // Pop and continue
    bytecode.push_back(encodeOpcode(OP_POP, seed));
    bytecode.push_back(encodeOpcode(OP_JUMP_IF_TRUE, seed));
    bytecode.push_back(-25); // Loop back

    // NOT FOUND
    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(0);
    bytecode.push_back(encodeOpcode(OP_HALT, seed));

    // FOUND
    bytecode.push_back(encodeOpcode(OP_FILE_CLOSE, seed));
    bytecode.push_back(encodeOpcode(OP_PUSH_IMM8, seed)); bytecode.push_back(1);
    bytecode.push_back(encodeOpcode(OP_HALT, seed));

    return {bytecode, strings};
}

static const string base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

string Deobfuscate(const std::string &input) {
    string key = "0XDALI";
    size_t keyLength = key.length();
    size_t inputLength = input.length();
    string output = input;

    for (size_t i = 0; i < inputLength; ++i) {
        output[i] = input[i] ^ key[i % keyLength];
    }

    return output;
}

string base64_decode(const std::string &input) {
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[base64Chars[i]] = i;
    string output;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

// Enhanced PIF detection via accessible side-effects
bool detectPIFSideEffects() {
    // Strategy 1: Check for PIF's injected classes in memory maps
    ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    string line;
    while (getline(maps, line)) {
        // class es.chiteroman.playintegrityfix
        if (line.find(Deobfuscate(base64_decode("VStqIiQgRD02LiEoXnY0LS0wWTYwJCs7WSw9JyUx")) ) != string::npos ||
            // class CustomKeyStoreSpi
            line.find(Deobfuscate(base64_decode("cy03NSMkez09EjgmQj0XMSU=")) ) != string::npos ||
            // class CustomProvider
            line.find(Deobfuscate(base64_decode("cy03NSMkYCorNyUtVSo=")) ) != string::npos ||
            // PlayIntegrityFix (plain text as fallback)
            line.find("PlayIntegrityFix") != string::npos ||
            line.find("playintegrityfix") != string::npos) {
            maps.close();
            return true;
        }
    }
    maps.close();

    // Strategy 2: Check for PIF-specific system properties (accessible to apps)
    const char* pifProps[] = {
        "ro.pif.enabled",
        "persist.pif.version",
        "persist.sys.pif.custom",
        "ro.product.first_api_level"  // PIF often modifies this
    };

    for (const char* prop : pifProps) {
        char value[PROP_VALUE_MAX] = {0};
        __system_property_get(prop, value);
        // Check if property exists and has suspicious values
        if (strlen(value) > 0) {
            // PIF sets first_api_level to trick SafetyNet
            if (strcmp(prop, "ro.product.first_api_level") == 0) {
                int apiLevel = atoi(value);
                // Suspicious if it's too old for the device
                if (apiLevel < 21 || apiLevel > 35) {
                    return true;
                }
            }
        }
    }

    // Strategy 3: Check for accessible module paths
    const char* accessiblePaths[] = {
        "/system/etc/pif.json",  // PIF config sometimes placed here
        "/data/local/tmp/pif.prop",
    };

    for (const char* path : accessiblePaths) {
        if (access(path, F_OK) == 0) {
            return true;
        }
    }

    return false;
}

bool runVM(const vector<uint8_t> &bytecode, const vector<string> &pathPool) {
    size_t ip = 0;

    while (ip < bytecode.size()) {
        uint8_t opcode = bytecode[ip++];
        switch (opcode) {
            case 0x01: {
                // Scan memory maps for injected PIF classes
                return detectPIFSideEffects();
            }
            case 0x02: {
                // Check accessible paths first
                for (const string &path : pathPool) {
                    if (access(path.c_str(), F_OK) == 0) {
                        return true;
                    }
                }
                // Fallback to memory-based detection
                return runVM({0x01}, pathPool);
            }
            case 0x03: {
                // New opcode: Check system properties for spoofing
                char brand[PROP_VALUE_MAX] = {0};
                char model[PROP_VALUE_MAX] = {0};
                __system_property_get("ro.product.brand", brand);
                __system_property_get("ro.product.model", model);

                // Check for common PIF spoofed values
                if (strcmp(brand, "google") == 0 || strcmp(brand, "Google") == 0) {
                    // Likely spoofed to pass integrity
                    if (strcmp(model, "Pixel 7") == 0 ||
                        strcmp(model, "Pixel 8") == 0 ||
                        strcmp(model, "Pixel 8 Pro") == 0) {
                        // These are common spoof targets
                        return true;
                    }
                }
                break;
            }
            default:
                return false;
        }
    }
    return false;
}


bool isZygiskActive() {
    // Check for Zygisk artifacts in memory maps
    const string knownZygiskLibs[] = {
            // "libzygisk.so" - actual Zygisk library
            Deobfuscate(base64_decode("XCYtSiEjKD8iEz03")),
            // "libmagiskhide.so"
            Deobfuscate(base64_decode("XCYtViwnKD8iXyotJS0REzcn")),
            // "lspd" - LSPosed framework
            Deobfuscate(base64_decode("XDsgQTw=")),
            // "LSPosed"
            Deobfuscate(base64_decode("XCNXYD8mPiAt")),
            // "[anon:zygisk]" - anonymous Zygisk mappings
            Deobfuscate(base64_decode("MCwnLic9CloqJSg6TileMQ==")),
            // "org.lsposed"
            Deobfuscate(base64_decode("LyonEGw6QDcmPyAtCg==")),
    };

    // open the /proc/self/maps
    ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    if (!maps.is_open()) return false;

    string line;
    while (getline(maps, line)) {
        for (const auto &lib : knownZygiskLibs) {
            if (line.find(lib) != string::npos) {
                maps.close();
                return true;
            }
        }
        // Also check for modified system libraries (Zygisk patches them)
        if (line.find("libandroid_runtime.so") != string::npos) {
            // Check if the mapping has suspicious permissions (rwx)
            if (line.find("rwxp") != string::npos) {
                maps.close();
                return true;
            }
        }
    }
    maps.close();

    // Check for Zygisk via environment variables
    if (getenv("ZYGISK_ENABLED") != nullptr ||
        getenv("MAGISK_VER_CODE") != nullptr) {
        return true;
    }

    // Check system property for Magisk/Zygisk
    char prop[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.magisk.zygisk", prop);
    if (strlen(prop) > 0 && strcmp(prop, "0") != 0) {
        return true;
    }

    return false;
}

string getProp(const char *prop_name) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(prop_name, value);
    return {value};
}

bool isBootloaderUnlocked() {
    // ro.boot.verifiedbootstate
    string verified_boot_state = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYyJD4gVjEhJS4mXyw3NS09VQ==")).c_str());
    // ro.boot.bootloader
    string bootloader = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYmLiM9XDclJSk7")).c_str());
    // ro.boot.veritymode
    string veritymode = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYyJD4gVzpmLiAtEg==")).c_str());
    // ro.boot.flash.locked
    string flash_locked = getProp(Deobfuscate(base64_decode("QjdqIyMmRHYmXDkmJylmXCcrQj0s")).c_str());

    // Device is compromised if ANY of these conditions are true:
    bool bootStateCompromised = !verified_boot_state.empty() && verified_boot_state != "green";
    bool bootloaderUnlocked = bootloader.find("unlock") != string::npos;
    bool verityDisabled = veritymode == "disabled";
    bool flashUnlocked = flash_locked == "0";

    return bootloaderUnlocked || bootStateCompromised || verityDisabled || flashUnlocked;
}

int isTraced() {
    // /proc/self/status
    ScopedFile f(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2M6RDkwND8=")).c_str(), "r");
    if (!f.isOpen())
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            return tracer_pid != 0;
        }
    }
    return -1;
}

int detectFridaSocket() {
    // open the /proc/net/unix
    ScopedFile fp(Deobfuscate(base64_decode("Hyg2Li9mXj0wbjknWSA=")).c_str(), "r");
    if (!fp.isOpen())
        return -1;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // "frida"
        if (strstr(line, Deobfuscate(base64_decode("ViotJS0==")).c_str()) ||
            // "xposed"
            strstr(line, Deobfuscate(base64_decode("SCgrMikt")).c_str()) ||
            // "re.frida"
            strstr(line, Deobfuscate(base64_decode("Qj1qJz4gVDk=")).c_str())) {
            return 1;
        }
    }
    return 0;
}

int detectKnownLibraries() {
    // open the /proc/self/maps
    ScopedFile fp(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")).c_str(), "r");
    if (!fp.isOpen())
        return -1;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // "frida"
        if (strstr(line, Deobfuscate(base64_decode("ViotJS0==")).c_str()) ||
            // "xposed"
            strstr(line, Deobfuscate(base64_decode("SCgrMikt")).c_str()) ||
            // "frida-server"
            strstr(line, Deobfuscate(base64_decode("Qj1qJz4gVDk=")).c_str())) {
            return 1;
        }
    }
    return 0;
}

int detectSuspiciousParent() {
    // /proc/self/status
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

    if (ppid == -1)
        return -1;

    char path[512];
    // /proc/%d/cmdline
    int written = snprintf(path, sizeof(path), Deobfuscate(base64_decode("Hyg2Li9mFTxrIiEtXDEqJA==")).c_str(), ppid);
    if (written < 0 || written >= static_cast<int>(sizeof(path)))
        return -1;

    ScopedFile fp2(path, "r");
    if (!fp2.isOpen())
        return -1;

    char cmdline[512];
    size_t bytesRead = fread(cmdline, 1, sizeof(cmdline) - 1, fp2);
    cmdline[bytesRead] = '\0';

    // frida
    if (strstr(cmdline, Deobfuscate(base64_decode("ViotJS0==")).c_str()))
        return 1;
    return 0;
}


extern "C"
JNIEXPORT jint JNICALL
f5d6d8a0228d2e7b607f28fefe95c77(JNIEnv *env, jobject obj) {
    if (isTraced())
        return -1;

    auto [fridaBytecode, fridaStrings] = compileFridaDetection();
    SecureVM fridaVM(fridaBytecode, fridaStrings);
    if (fridaVM.execute()) {
        return -1;
    }

    auto [zygiskBytecode, zygiskStrings] = compileZygiskDetection();
    SecureVM zygiskVM(zygiskBytecode, zygiskStrings);
    bool zygiskDetected = zygiskVM.execute();

    auto [pifBytecode, pifStrings] = compilePIFDetection();
    SecureVM pifVM(pifBytecode, pifStrings);
    bool pifDetected = pifVM.execute();

    bool bootloaderUnlocked = isBootloaderUnlocked();

    if (zygiskDetected || pifDetected || bootloaderUnlocked) {
        return 1;
    }

    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    // com.example.playIntegrityFixDetector.MainActivity
    static const string className = Deobfuscate(base64_decode("UzcpbikxUTU0LSlmQDQlOAUnRD0jMyU9SR4tOQgsRD0nNSM7HxUlKCIIUywtNyU9SQ=="));
    // isIntegrityTampered
    static const string methodName = Deobfuscate(base64_decode("WSsNLzgsVyotNTUdUTU0JD4sVA=="));

    jclass clazz = env->FindClass(className.c_str());
    if (!clazz)
        return JNI_ERR;

    static const JNINativeMethod methods[] = {
            {const_cast<char*>(methodName.c_str()), const_cast<char*>("()I"), reinterpret_cast<void *>(f5d6d8a0228d2e7b607f28fefe95c77)}
    };

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) < 0)
        return JNI_ERR;

    return JNI_VERSION_1_6;
}

