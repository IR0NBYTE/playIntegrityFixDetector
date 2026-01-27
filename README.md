# Play Integrity Fix Detector

An Android security app that detects Play Integrity Fix (PIF) modules running on a device. Built with native C++ and Java, it uses runtime obfuscation and behavioral checks to identify environment modifications that bypass Google's Play Integrity API.

---

## Purpose

Google's Play Integrity API verifies device and app integrity. Play Integrity Fix is a Zygisk module that spoofs system properties and manipulates the Android Keystore to pass these checks. This app detects when PIF is active on a device.

## Requirements

- Android 7.0 (API 24) and above.
- Native library built with NDK r25+.

---

## Release Build

The pre-built APK is available in the `/release` folder.

---

## Project Structure

- `MainActivity.java` - Handles UI and triggers security checks
- `native-lib.cpp` - Native detection logic for PIF, Zygisk, Frida, debuggers, and bootloader status

---

## UI Flow

The app runs several security checks on startup:

- Root detected → Shows alert and exits
- Debug tools detected → Shows alert and exits
- PIF detected → Shows alert and exits
- All checks pass → Shows success dialog

---

## How PIF Works

Based on reverse engineering the PIF implementation (https://github.com/jyotidwi/PlayIntegrityFix), here's how it bypasses integrity checks:

**Play Integrity Fix operates as a Zygisk module:**

1. Hooks `__system_property_read_callback` to spoof build properties (`ro.build.version.sdk`, `ro.build.version.security_patch`, `ro.build.id`)

2. Injects `classes.dex` at runtime into `com.google.android.gms.unstable`

3. Uses reflection in `EntryPoint.java` to modify `Build` fields and inject a custom `KeyStoreSpi` provider into AndroidKeyStore

---

## Detection Methods

### 1. PIF Detection

PIF injects DEX files at runtime using `InMemoryDexClassLoader` and modifies system classes via reflection:
- `android.os.Build` and `android.os.Build.VERSION`
- `AndroidKeyStore` provider

**Detection approach:**

Scans `/proc/self/maps` for PIF class names:
- `es.chiteroman.playintegrityfix`
- `CustomKeyStoreSpi`
- `CustomProvider`

**Implementation:**

The detection logic runs inside a custom bytecode VM to protect against static analysis and runtime hooking. Detection operations are encoded as VM opcodes rather than direct function calls, making it harder to bypass with Frida or Xposed.

### 2. Bootloader Unlock Detection

An unlocked bootloader allows unsigned system images and custom recovery, which compromises device integrity. PIF typically requires an unlocked bootloader to install.

**Detection approach:**

Checks system properties:
- `ro.boot.verifiedbootstate` (should be "green")
- `ro.boot.veritymode` (should not be "disabled")
- `ro.boot.flash.locked` (should be "1")
- `ro.boot.bootloader` (should not contain "unlock")

---

### 3. Zygisk Detection

Zygisk is the framework that allows PIF to inject code into system processes. Detecting Zygisk often means PIF is present.

**Detection approach:**

Scans `/proc/self/maps` for Zygisk libraries:
- `libzygisk.so`
- `libmagiskhide.so`
- `lspd` (LSPosed)
- `[anon:zygisk]` memory mappings

Checks environment variables:
- `ZYGISK_ENABLED`
- `MAGISK_VER_CODE`

Verifies system properties:
- `ro.magisk.zygisk`

---

## Security & Obfuscation

Multiple layers of protection make the app difficult to reverse engineer or bypass:

**String Obfuscation:**
Sensitive strings are XOR-encoded with base64 and only decoded at runtime, preventing static extraction of class names and method signatures.

**Root Detection:**
Uses RootBeer library to detect rooted devices and emulators. ProGuard rules preserve RootBeer classes while obfuscating the rest.

**ProGuard Configuration:**
- Aggressive class and method renaming
- Stripped logging calls
- Removed unused code
- Protected native method signatures

**Anti-Debug & Anti-Frida:**

- `isTraced()` - Parses `/proc/self/status` for `TracerPid` to detect attached debuggers
- `detectFridaSocket()` - Scans `/proc/net/unix` for Frida/Xposed socket names
- `detectKnownLibraries()` - Checks `/proc/self/maps` for hooking framework libraries
- `detectSuspiciousParent()` - Verifies parent process isn't Frida

**VM-Based Detection:**
Detection logic runs as bytecode in a custom VM with 30+ opcodes for file I/O, string operations, and system checks. This makes hooking significantly harder since there are no direct function calls to intercept.

**Native Symbol Stripping:**
CMake flags hide native symbols and method names:
```cmake
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fvisibility=hidden)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -Wl,--strip-all)
```

**Manual JNI Registration:**

The main native function `f5d6d8a0228d2e7b607f28fefe95c77` uses manual JNI registration instead of default naming conventions:
- Function name is a random hex string
- Class and method names are base64-encoded with XOR obfuscation
- Decoded at runtime in `JNI_OnLoad`
- Prevents static analysis tools from finding JNI entry points

Return values:
- `-1` - Debugger or Frida detected
- `1` - PIF, Zygisk, or unlocked bootloader detected
- `0` - Clean device

---

## Testing

A demo video is included in the repository showing the app detecting PIF on a rooted device.

