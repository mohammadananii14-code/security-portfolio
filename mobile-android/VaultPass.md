# CTF Writeup — VaultPass (Android)

**Category:** Mobile / Android Application Security
**Difficulty:** _[fill in]_
**Skills:** JNI native method mapping, anti-tamper/anti-debug bypass, Frida dynamic instrumentation

---

## Overview

VaultPass required mapping native JNI methods to understand an app-level anti-tamper chain,
then using Frida to hook and bypass the protections at runtime in order to reach and extract
protected data (credentials/flag).

**Target app:** `[package name]`
**Source:** `[link or CTF platform name]`

---

## Environment & Tools

- Genymotion (rooted AVD)
- `jadx-gui` — static Java/Kotlin analysis
- Ghidra — native library analysis
- Frida + `frida-server` (version-matched to client) — dynamic instrumentation
- Objection — supporting runtime exploration
- `frida-env` virtualenv for hook script development

---

## Methodology

### 1. Static Analysis — Mapping the Anti-Tamper Chain

Decompiled the APK with `jadx-gui` and identified multiple integrity checks run before the
protected "vault" functionality became accessible:

- `[Root detection check — e.g. su binary / Magisk path checks]`
- `[Debugger detection — e.g. Debug.isDebuggerConnected() / TracerPid check]`
- `[Signature/tamper check — e.g. app signature hash comparison]`

```java
// jadx-gui excerpt
if (isRooted() || isDebuggerAttached() || !checkSignature()) {
    // lock / kill / feed fake data
}
```

Each check fed into a shared gate before native methods (`System.loadLibrary`, JNI calls) were
invoked to decrypt or reveal the vault contents.

### 2. Mapping Native JNI Methods

Cross-referenced Java-side `native` method declarations against symbols in the bundled `.so` via
Ghidra to understand which native function performed the actual decryption/validation, versus
which were decoys or secondary checks.

```java
public native boolean [nativeCheckMethod](...);
public native String [nativeDecryptVault](...);
```

`[Note which native method turned out to be the real gate vs. a distraction.]`

### 3. Building the Frida Hook Chain

Rather than patching the APK, hooked each Java-layer check at runtime to force the "pass" path,
iterating hook-by-hook as each successive protection surfaced:

```javascript
// hook.js — iterative pattern
Java.perform(function () {
    var target = Java.use("[com.package.SecurityChecks]");

    target.isRooted.implementation = function () {
        console.log("[*] isRooted() bypassed");
        return false;
    };

    target.isDebuggerAttached.implementation = function () {
        console.log("[*] isDebuggerAttached() bypassed");
        return false;
    };

    target.checkSignature.implementation = function () {
        console.log("[*] checkSignature() forced true");
        return true;
    };
});
```

```bash
frida -U -f [package] -l hook.js --no-pause
```

### 4. Reaching and Extracting the Vault Data

With all gating checks neutralized, the app proceeded to the native decryption call. Hooked the
native decrypt method's return value directly (rather than reversing the crypto routine itself)
to capture the plaintext output as it crossed back into the Java layer:

```javascript
var nativeLib = Process.findModuleByName("lib[name].so");
Interceptor.attach(nativeLib.findExportByName("[nativeDecryptVault]"), {
    onLeave: function (retval) {
        console.log("[*] Decrypted vault contents: " + retval.readCString());
    }
});
```

Output: `[decrypted vault contents / flag]`

---

## Flag

```
[FLAG]
```

---

## Root Cause

- Anti-tamper logic (root/debugger/signature checks) was implemented entirely client-side in
  Java, with no server-side validation — trivially bypassable via Frida method hooking since the
  app's control flow itself could be overridden at runtime.
- Sensitive decryption occurred natively but exposed plaintext output directly across the
  JNI boundary, making it interceptable regardless of how well the checks upstream were hardened.

## Remediation

- Client-side root/debugger/tamper checks should be treated as a speed bump, not a security
  boundary — critical logic and secrets should never depend on them alone.
- Consider RASP (runtime application self-protection) techniques or native-layer integrity
  checks that are harder to hook (e.g. checks performed and enforced entirely in native code,
  inlined and obfuscated).
- Avoid returning sensitive plaintext across the JNI boundary in a single interceptable call;
  where possible, keep sensitive data resident in native memory only as long as needed.

## Notes / Lessons Learned

- First real hands-on chain of multiple Frida hooks layered together, rather than a single
  bypass — reinforced iterative hook development (test one check, confirm bypass, move to the
  next).
- Solidified the `frida-env` virtualenv workflow and the importance of keeping Frida client/server
  versions aligned to avoid silent hook failures.
- Distinguishing the "real" native gate from decoy checks was the main time sink — worth doing a
  full static pass of all native method call sites before writing any hooks next time.
