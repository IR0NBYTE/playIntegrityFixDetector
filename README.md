# Play Integrity Fix Native Detector

This project is a native Android application that detects **Play Integrity Fix (PIF)**. It leverages a combination of native C++ and Java code, runtime obfuscation, and behavioral heuristics to catch sophisticated environment modifications commonly used to bypass Google's Play Integrity API.

---

## Purpose

Google's Play Integrity API is designed to assess the integrity of the device and app environment. Tools like **Play Integrity Fix (PIF)** aim to spoof key system properties and manipulate the Android Keystore to falsify device integrity checks. The goal of this app is to detect the PIF on android phones.

## Requirements

- Android 7.0 (API 24) and above.
- Native library built with NDK r25+.

---

## Project Structure
he project has a Java component (MainActivity.java) that handles the UI and triggers native detection, and a C++ component (native-lib.cpp) that detects PIF, Frida, debuggers, Zygisk, and tampering.

---

## UI Flow :

The main activity (`MainActivity.java`) provides a simple interface:

- **If root is detected** → Displays root alert and exits.
- **If debug tools are detected** → Displays anti-debug alert and exits.
- **If PIF is detected** → Shows PIF Detection alert and exits.
- **If all checks pass** → Shows "Integrity Passed" dialog.

---

## How PIF Works : 

After Reading around the internet and reverse engineering a little the code of the PIF from this repo that gives a try on the implemntation of PIF : https://github.com/jyotidwi/PlayIntegrityFix I conclude those 3 pointes :

**Play Integrity Fix (PIF)** operates via a Zygisk module:

1. **Hooks `__system_property_read_callback`** to spoof properties like:
   - `ro.build.version.sdk`
   - `ro.build.version.security_patch`
   - `ro.build.id`

2. **Injects `classes.dex`** at runtime into `com.google.android.gms.unstable`.

3. **Uses reflection** in `EntryPoint.java` to spoof:
   - `Build.MODEL`, `Build.ID`, `Build.VERSION.SDK_INT`
   - AndroidKeyStore's internal `KeyStoreSpi` via a custom `Provider`

---

## Detection Logic for the different components in my native application code

### 1. **Play Integrity Fix (PIF) Detection**
PIF works by injecting a DEX at runtime via `InMemoryDexClassLoader` and modifying system fields using reflection. It targets:
- `android.os.Build`
- `android.os.Build.VERSION`
- `AndroidKeyStore` provider

My native code performs the following:

- Scans process memory and loaded class paths for injected `es.chiteroman.playintegrityfix`, `CustomKeyStoreSpi`, `CustomProvider`.
- Hooks libart/libbinder internals to detect runtime Java class injection.
- Detects the presence of injected Keystore providers.

**How I implemented it:**  
- wrote a little VM that executes bytecode pointing to some sensitive detection logic, protecting it from direct static analysis.
- It obfuscates strings and control flow via encoded instructions.
- The VM interacts with JNI to fetch runtime values and perform the layered checks required to detect the PIF.

### 2. **Bootloader Unlock Detection** (`isBootloaderUnlocked`)

**What I detect:**  
Whether the device bootloader is unlocked, which compromises the device security and allows tampering cuz that might get us also to a PIF.

**How I implemented it:**  
The native function `isBootloaderUnlocked()` performs checks on system properties and device files that indicate bootloader unlock status, such as:
- Reading system properties like `ro.boot.verifiedbootstate` or `ro.boot.veritymode`.
- Comparing with expected values to identify unlocked states.

**Analogy with PIF:**  
Similar to how PIF hooks and overrides system properties (`__system_property_read_callback`), my code reads and verifies bootloader-related properties to detect if the device’s integrity has been compromised at the boot level.

---

### 3. **Zygisk Module Detection** (`isZygiskActive`)

**What I detect:**  
Whether the process is running under Zygisk module, which enables code injection and runtime modification of processes related also to PIF so I tought we have to detect that.

**How I implemented it:**  
The native function `isZygiskActive()` detects:
- Presence of Zygisk-specific environment variables or process maps.
- Hooks or indicators left by Zygisk in memory or linked libraries.
- Checks for common artifacts such as loaded Zygisk shared libraries or special system properties modified by Zygisk.

**Analogy with PIF:**  
Just like PIF targets specific apps such as (`com.google.android.gms.unstable`) and injects code via Zygisk, my detection inspects the process environment and runtime context to catch signs of Zygisk manipulation.

---

## Obfuscation techniques and security measures I implemented to make the app robust and difficult to bypass

To evade static analysis, reverse engineering, and runtime tampering, I applied multiple layers of obfuscation and protection both in native and Java code:

- **String Literals Obfuscation:**  
  All sensitive strings are encoded at compile time using a one-time pad and are only decoded at runtime in memory. This prevents easy extraction of keys, class names, or method signatures by static tools.

- **Anti-Root Detection via RootBeer:**  
  The app integrates the RootBeer library to detect rooted environments and emulator usage. ProGuard rules are set to keep RootBeer intact, ensuring the detection logic is preserved.

- **ProGuard Obfuscation:**

The app leverages ProGuard with a custom rules file to further obfuscate the Java bytecode and optimize the app if you check that file in the src code you will notice:

- The rules aggressively rename classes and methods while preserving essential Android components and native method signatures.
- RootBeer classes are kept intact to maintain runtime root detection functionality.
- Logging calls are stripped out to avoid leaking debugging information.
- String obfuscation is applied by adapting class strings and resource filenames to hinder static extraction.
- Unused classes and methods are removed to reduce app size and eliminate dead code paths.

- **Anti-Frida and Anti-Debugging Techniques implemented in native code:**

The native integrity check includes multiple functions designed to detect runtime debugging and hooking attempts, especially those using Frida or similar instrumentation frameworks:

- The function `isTraced()` reads `/proc/self/status` to check if the process is currently being traced (debugged):
  - It parses the `TracerPid` field to determine if a debugger is attached.
  - Returns true if tracing is detected, blocking debugging attempts.

- The function `detectFridaSocket()` scans `/proc/net/unix` for UNIX domain sockets linked to known hooking tools:
  - It looks for socket names like `"frida"`, `"xposed"`, and `"re.frida"`.
  - Detecting these indicates an active Frida or Xposed hooking environment and we can add more to the list.

- The function `detectKnownLibraries()` inspects `/proc/self/maps` for loaded libraries associated with hooking frameworks:
  - Checks for library names such as `"frida"`, `"xposed"`, and `"frida-server"` and we can add more to the list.
  - Presence of these libraries signals possible runtime tampering.

- The function `detectSuspiciousParent()` reads the parent process information from `/proc/[ppid]/cmdline`:
  - It verifies if the parent process name matches `"frida"` and we can add more to the list in the future.
  - This helps detect if the app was launched or controlled by suspicious instrumentation tools.

- **Running the Integrity detection code inside of a little VM that has 2 opcodes:**  
  Sensitive detection logic is implemented inside a simple bytecode VM executed at runtime in native code (`runVM()` function). This adds a layer of indirection making static and dynamic analysis significantly slightly harder since I can't write one in 7 days I wanted to just show the usage of such a thing that can make the reversing harder.

- **Native Library Symbol Stripping:**  
  The native build uses the following CMake flags to hide native symbols and method names:  
  ```cmake
  target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fvisibility=hidden)
  target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -Wl,--strip-all)

- **Usage of the native integrity check function with obfuscation and manual JNI registration :**

The native function `f5d6d8a0228d2e7b607f28fefe95c77` implements the core runtime integrity checks in a heavily obfuscated manner, both in its implementation and how it is exposed to the Java layer:

- The function name `f5d6d8a0228d2e7b607f28fefe95c77` I randomaly put will help:
  - Hide the function’s purpose from native symbol tables.
  - Along with compiler flags that we used earlier will make sure getting to the library will become a little diffcult.

- The function will return:
  - 1 if it detects the PIF.
  - -1 if it detects any debugger hooked to the process of the app. 
  - 0 if everything is ok.

- Instead of default JNI naming, the function is **manually registered** inside `JNI_OnLoad`:
  - Java class and method names are stored as **base64-encoded and further obfuscated strings**.
  - These are decoded and deobfuscated at runtime to reveal real names.
  - This will prevent static string scanning and analysis for JNI symbols when using static analysis tools.

---

## Testing Process

A walkthrough video is attached to this repo that showcases the testing process.

