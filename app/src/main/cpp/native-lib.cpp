#include <jni.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sys/system_properties.h>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

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

bool runVM(const vector<uint8_t> &bytecode, const vector<string> &pathPool) {
    size_t ip = 0;

    while (ip < bytecode.size()) {
        uint8_t opcode = bytecode[ip++];
        switch (opcode) {
            case 0x01: {
                // /proc/self/maps
                ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
                string line;
                while (getline(maps, line)) {
                    // class es.chiteroman.playintegrityfix
                    if (line.find(Deobfuscate(base64_decode("VStqIiQgRD02LiEoXnY0LS0wWTYwJCs7WSw9JyUx")) ) != string::npos ||
                        // class CustomKeyStoreSpi
                        line.find(Deobfuscate(base64_decode("cy03NSMkez09EjgmQj0XMSU=")) ) != string::npos ||
                        // class CustomProvider
                        line.find(Deobfuscate(base64_decode("cy03NSMkYCorNyUtVSo=")) ) != string::npos ||
                        // kdrag0n.safetynetfix
                        line.find(Deobfuscate(base64_decode("VD0ybyctQjkjcSJnQzkiJDgwXj0wJyUx")) ) != string::npos ||
                        // io.github.chiteroman.playintegrityfix
                        line.find(Deobfuscate(base64_decode("WTdqJiU9WC0mby8hWSwhMyMkUTZqMSAoSTEqNSkuQjEwOCogSA==")) ) != string::npos) {
                        return true;
                    }
                }
                break;
            }
            case 0x02: {
                for (const string &path : pathPool) {
                    if (access(path.c_str(), F_OK) == 0) {
                        return true;
                    }
                }
                return runVM({0x01}, pathPool);
            }
            default:
                return false;
        }
    }
    return false;
}


bool isZygiskActive() {

    // libs to check zygisk64/zygisk32
    const string knownZygiskLibs[] = {
            // "zygisk64"
            Deobfuscate(base64_decode("SiEjKD8iBmw=")),
            // "zygisk32"
            Deobfuscate(base64_decode("SiEjKD8iA2o=")),
    };
    // open the /proc/self/maps
    ifstream maps(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")));
    string line;
    while (getline(maps, line)) {
        for (const auto &lib : knownZygiskLibs) {
            if (line.find(lib) != string::npos) {
                return true;
            }
        }
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
    return (verified_boot_state != "green" || bootloader.find("unlock") != string::npos);
}

int isTraced() {
    // /proc/self/status
    FILE *f = fopen(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2M6RDkwND8=")).c_str(), "r");
    if (!f)
        return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(f);
            return tracer_pid != 0;
        }
    }
    fclose(f);
    return -1;
}

int detectFridaSocket() {
    // open the /proc/net/unix
    FILE *fp = fopen(Deobfuscate(base64_decode("Hyg2Li9mXj0wbjknWSA=")).c_str(), "r");
    if (!fp)
        return -1;

    // look up for frida/xposed/re.frida
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // "frida"
        if (strstr(line, Deobfuscate(base64_decode("ViotJS0==")).c_str()) ||
            // "xposed"
            strstr(line, Deobfuscate(base64_decode("SCgrMikt")).c_str()) ||
            // "re.frida" (not obfuscated)
            strstr(line, Deobfuscate(base64_decode("Qj1qJz4gVDk=")).c_str())) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int detectKnownLibraries() {
    // open the /proc/self/maps
    FILE *fp = fopen(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2MkUSg3")).c_str(), "r");
    if (!fp)
        return -1;

    // look up for frida/xposed/re.frida
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // "frida"
        if (strstr(line, Deobfuscate(base64_decode("ViotJS0==")).c_str()) ||
            // "xposed"
            strstr(line, Deobfuscate(base64_decode("SCgrMikt")).c_str()) ||
            // "frida-server"
            strstr(line, Deobfuscate(base64_decode("Qj1qJz4gVDk=")).c_str())) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int detectSuspiciousParent() {
    // /proc/self/status
    FILE *fp = fopen(Deobfuscate(base64_decode("Hyg2Li9mQz0oJ2M6RDkwND8=")).c_str(), "r");
    if (!fp)
        return -1;

    char line[256];
    pid_t ppid = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = atoi(line + 5);
            break;
        }
    }
    fclose(fp);
    if (ppid == -1)
        return -1;

    char path[256];
    // /proc/%d/cmdline
    snprintf(path, sizeof(path), Deobfuscate(base64_decode("Hyg2Li9mFTxrIiEtXDEqJA==")).c_str(), ppid);
    fp = fopen(path, "r");
    if (!fp)
        return -1;

    char cmdline[256];
    fread(cmdline, sizeof(cmdline), 1, fp);
    fclose(fp);

    // frida
    if (strstr(cmdline, Deobfuscate(base64_decode("ViotJS0==")).c_str()))
        return 1;
    return 0;
}

int detectFridaPort() {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042);
    inet_aton("127.0.0.1", &sa.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
        close(sock);
        return 1;
    }

    close(sock);
    return 0;
}

extern "C"
JNIEXPORT jint JNICALL
f5d6d8a0228d2e7b607f28fefe95c77(JNIEnv *env, jobject obj) {
    if (isTraced() || detectFridaSocket() || detectSuspiciousParent() || detectKnownLibraries() || detectFridaPort())
        return -1;
    vector<uint8_t> bytecode = {0x02};
    vector<string> pathPool = {
            // /data/local/tmp/PlayIntegrityFix.apk
            Deobfuscate(base64_decode("HzwlNS1mXDcnICBmRDU0bhwlUSENLzgsVyotNTUPWSBqIDwi")),
            // /data/adb/modules/PlayIntegrityFix
            Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mYDQlOAUnRD0jMyU9SR4tOQ==")),
            // /data/adb/lspd/modules/PlayIntegrityFix
            Deobfuscate(base64_decode("HzwlNS1mUTwmbiA6QDxrLCMtRTQhMmMZXDk9CCI9VT82KDgwdjE8")),
            // /data/adb/lspd/modules_update/PlayIntegrityFix
            Deobfuscate(base64_decode("HzwlNS1mUTwmbiA6QDxrLCMtRTQhMhM8QDwlNSlmYDQlOAUnRD0jMyU9SR4tOQ==")),
            // /data/adb/modules/playintegrityfix
            Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDQlOCUnRD0jMyU9ST4tOQ==")),
            // /data/adb/modules/pif-fork
            Deobfuscate(base64_decode("HzwlNS1mUTwmbiEmVC0oJD9mQDEibComQjM="))
        
    };
    if (runVM(bytecode, pathPool) || isZygiskActive() || isBootloaderUnlocked())
        return 1;
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    // class com.example.playIntegrityFixDetector.MainActivity
    jclass clazz = env->FindClass(Deobfuscate(base64_decode("UzcpbikxUTU0LSlmQDQlOAUnRD0jMyU9SR4tOQgsRD0nNSM7HxUlKCIIUywtNyU9SQ==")).c_str());
    if (!clazz)
        return JNI_ERR;

    static const JNINativeMethod methods[] = {
            // isIntegrityTampered
            {Deobfuscate(base64_decode("WSsNLzgsVyotNTUdUTU0JD4sVA==")).c_str(), "()I", reinterpret_cast<void *>(f5d6d8a0228d2e7b607f28fefe95c77)}
    };

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) < 0)
        return JNI_ERR;

    return JNI_VERSION_1_6;
}

