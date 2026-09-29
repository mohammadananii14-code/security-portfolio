# HackTheBox — SAW (Android)

**Category:** Mobile / Android Application Security
**Difficulty:** _[fill in]_
**Skills:** Native library reverse engineering, XOR key recovery, exported component exploitation

---

## Overview

SAW is an Android CTF challenge requiring reverse engineering of a native (`.so`) library to
recover an XOR-encoded key, followed by exploitation of an insecurely exported Android component
to retrieve the flag.

**Target app:** `[package name, e.g. com.htb.saw]`
**APK source:** `[link or HTB challenge name]`

---

## Environment & Tools

- Genymotion (Android emulator)
- `jadx-gui` — Java/Kotlin decompilation
- Ghidra — native `.so` reverse engineering
- `adb` — component interaction / logcat
- `[Frida / Objection if used]`

---

## Methodology

### 1. Static Triage

Unpacked the APK and reviewed `AndroidManifest.xml` for exported components:

```xml
<!-- exported activity found -->
<activity android:name="[ActivityName]" android:exported="true" ... />
```

`[Describe what made this activity interesting — e.g. it read an intent extra and compared it
against a decoded value before revealing the flag.]`

### 2. Locating the Native Library

Decompiling with `jadx-gui` showed a call into a bundled native library (`lib[name].so`) via
`System.loadLibrary(...)`, with a JNI method responsible for decoding a stored value at runtime.

```java
// jadx-gui excerpt
static {
    System.loadLibrary("[libname]");
}
public native String [methodName](...);
```

### 3. Reverse Engineering the `.so` in Ghidra

Loaded the extracted `lib[name].so` into Ghidra and located the JNI-exported function
(`Java_com_..._[methodName]`). Traced the decompiled logic to identify an XOR loop operating over
a hardcoded byte array using a single-byte (or repeating) key.

```c
// Ghidra decompilation excerpt (annotate the actual XOR routine here)
for (i = 0; i < len; i++) {
    out[i] = data[i] ^ key[i % key_len];
}
```

**Recovered key:** `[value]`

### 4. Recovering the Decoded String

Reimplemented the XOR routine in Python to recover the plaintext value the app compares against:

```python
data = bytes([...])   # extracted byte array
key  = b"[recovered key]"

decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
print(decoded)
```

Output: `[decoded value]`

### 5. Exploiting the Exported Activity

With the decoded value in hand, launched the exported activity directly via `adb`, passing the
value as the expected intent extra — bypassing the app's normal entry flow and any client-side
gating logic:

```bash
adb shell am start -n [package]/[ActivityName] \
  --es "[extra_key]" "[decoded value]"
```

This returned/displayed the flag directly, since the check the activity relied on was entirely
client-side and reachable by any component with permission to start it.

---

## Flag

```
[FLAG]
```

---

## Root Cause

- Sensitive comparison value was recoverable via static reverse engineering of an unprotected
  native library (weak/no obfuscation, hardcoded XOR key).
- The activity was exported without a permission guard or signature-level protection, so any
  local component (or `adb`) could invoke it directly and bypass intended app flow.

## Remediation

- Do not rely on client-side secret comparisons for access control — validate server-side where
  possible.
- Set `android:exported="false"` on activities not intended for external/inter-app use, or
  enforce a custom signature-level permission.
- Obfuscate/harden native code (e.g. string encryption, control-flow flattening) if a
  client-side secret is unavoidable — though this only raises the bar, it doesn't remove the
  fundamental issue.

## Notes / Lessons Learned

- Practiced tracing JNI calls from Java into native `.so` code and recovering simple XOR-based
  obfuscation manually in Ghidra rather than relying on a decompiler shortcut.
- Reinforced that exported component review should always be paired with native reverse
  engineering when an app bundles native code — the vulnerable logic isn't always in the Java
  layer.
