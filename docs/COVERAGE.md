# Detection coverage

What each flag actually observes, whether it can fire from an unprivileged
untrusted_app, and what defeats it. This file exists because a check that
"exists" is not a check that "fires", and a README that implies otherwise is the
failure this project keeps auditing for.

Measured on a Pixel 7a (lynx), Android 15, Magisk 28.1 with Shamiko v1.2.1 and
Vector v2.2, no keystore spoofing module, unless a row says otherwise.

The attestation-record rows added in 2.9 were additionally measured on two
stock, locked, green-boot handsets from other vendors, because several of them
could not be justified from one device family:

| Device | Android | SDK | first_api_level | keystore feature | Attested versions | system / vendor patch |
|---|---|---|---|---|---|---|
| Pixel 7a (lynx) | 15 | 35 | 33 | 300, StrongBox 300 | schema 300, KeyMint 300 | 2024-12-05 / 2024-12-05 |
| Samsung SM-G780G (r8q) | 13 | 33 | 29 | 4, StrongBox 4 | schema 3, Keymaster 4.0 | 2024-09-01 / 2024-09-01 |
| Motorola moto g04 (lion) | 14 | 34 | 34 | 200 | schema 200, KeyMint 200 | 2025-08-05 / 2025-04-05 |

The keystore probe rows added in 3.0 were re-measured on that same station over
adb, which is where the StrongBox and identifier arms get their positive
witnesses: the Pixel 7a serves StrongBox and performs device-properties
attestation, the SM-G780G serves StrongBox at the Keymaster 4.0 generation, and
the moto g04 performs device-properties attestation with no secure element.

The two rows added in 3.1 were measured on a locally attached handset and three
emulator images, because the station was unreachable for that work and because
what each arm needed was a different kind of device rather than another retail
flagship:

| Device | Android | SDK | first_api_level | keystore feature | What it contributes |
|---|---|---|---|---|---|
| Samsung SM-A065F (a06) | 14 | 34 | 34 | 100, no StrongBox | A genuine mdfpp TEE on an RKP chain, bootloader unlocked, **rooted**: Magisk 30.6 with Shamiko and Zygisk Next, and frida-server listening on 27042. The only device here whose EC chain anchors to a pinned Google root, so the only one that opens the companion algorithm gate |
| `Pixel3_adb_root_test_sdk30` | 11 | 30 | 30 | none declared | AOSP software keymaster, pre-RKP. Serves a DIFFERENT attestation root per key algorithm |
| `Pixel3_malware_sdk32` | 12L | 32 | 31 | 41 | The same two software roots while declaring `hardware_keystore` 41, which is why the feature flag is not a usable gate |
| `Pixel3_malware_sdk34` | 14 | 34 | 34 | 300 | The RKP `Droid Unregistered Device CA` chain, one root for both algorithms |

The SM-A065F is an unlocked-bootloader **rooted** unit, so it witnesses
keystore- and maps-shaped arms and is explicitly NOT a witness for verified-boot,
lock-state, root or hook arms. It is a positive witness for those last two: the
root, hider and frida families all fire on it and are right to.

This row said "stock and unrooted" from 2026-10-19, when it was added, until
2026-10-26. That was wrong, and wrong in the direction that matters, because it
described the device this file leans on for genuine-negative measurements. The
error came from inferring root state from an unprivileged shell: `/data/adb` was
unreadable and the shell ran as uid 2000, which is true of a rooted device as
well. `su -c id` was never run. It returns uid 0 in `u:r:magisk:s0`.
`docs/PLAN.md` and the CODE_INTEGRITY row below had said "rooted Samsung A06"
all along, so the file contradicted itself for a week.

The measurements taken on it stand, and one of them is stronger than claimed:
the 68 property areas read as shared on a device that is running Magisk, rather
than on a stock one.

Every attestation-record row below is silent on all three station handsets. The
root and hook rows are not in scope for that claim: the Pixel in this population is the
rooted, bootloader-unlocked test unit, and the rows that say so fire on it.

Three measurements from that population are load-bearing and are cited in the
rows that rest on them:

- The attested verifiedBootHash equals `ro.boot.vbmeta.digest` on all three,
  across three vendors, which is what the boot-hash arm was waiting for. The
  arm fires only when both sides are real 32-byte digests that differ; an
  all-zero or odd-length attested hash is reported, not called.
- `ro.vendor.build.security_patch` reads empty to the app on the Pixel and the
  moto g04 and non-empty on the Samsung, so its readability is a per-vendor
  sepolicy decision and no finding may depend on it.
- The Samsung's clock is a year behind and the moto g04's is thirteen months
  behind. Both are genuine retail devices. Any check that compares a
  certificate against the device clock would have flagged them.

## Flags

| Flag | Sub-checks | Fires unprivileged | Evidence | Known counter |
|---|---|---|---|---|
| DEBUGGER | TracerPid, FLAG_DEBUGGABLE (release only) | Yes | Both work in-process | Any debugger that clears TracerPid |
| FRIDA | TCP connect to 27042/27043, thread names, maps scan, parent cmdline, legacy /proc/net/tcp | Partly | Port, thread and maps checks work in-process. Two arms fail open: the parent-cmdline read needs /proc/<ppid>/cmdline, which hidepid denies, and the /proc/net/tcp scan is filtered empty for untrusted_app on Android 10+. Where that table is readable (API 24 to 28, device-wide) reason 203 fires only on a row whose local port is 27042 or 27043 and whose state is 0A (LISTEN); it used to match the port anywhere on the line, so another app's connection to a remote server on 27042 counted | A gadget on a non-default port with renamed threads |
| ZYGISK | maps needles, env vars, ro.magisk.zygisk, /data/adb probes, root-manager packages, su and busybox paths, module names from mountinfo | Yes | Fires on the test device via maps and the new mountinfo module-name harvest. Busybox (306) is noted only beside another arm in this group and never sets the bit alone, because OEMs ship it in /system/bin, /system/xbin or /vendor/bin of production images | Trace-cleaning Zygisk implementations, denylist, a renamed manager package |
| ROOT_HIDER | mountinfo source and mount-root analysis, OverlayFS on /system, anonymous rwxp count | Yes | Fires on the test device: 6 tmpfs mounts over system partitions whose source is not tmpfs, plus one /adb/ bind that leaks the module name. Reason 905 adds the case where a root tmpfs shadows nothing at all, which is what a module-less install looks like and what returned a mask of zero on a live Magisk 31.1 emulator. It matches the mount source against a needle rather than reporting any non-`tmpfs` source, because an unrooted API 23 image mounts `/sys/fs/cgroup` as `- tmpfs none` and the general rule would have convicted it. See the section on it below | The app being on the denylist, and SUSFS sus_mount, which falsifies mountinfo in kernel. 905 specifically is defeated by renaming the mount source, which is one line for whoever ships it |
| BOOTLOADER | verifiedbootstate, flash.locked, veritymode, vbmeta.device_state, ro.debuggable, ro.secure, oem_unlock_allowed | Partly | Reads what the properties say. ro.secure is labelled userdebug_or_eng_prop and is denied to untrusted_app, so that arm silently no-ops. oem_unlock_allowed (508) is the Developer options switch, which a locked retail phone can have on, so it is noted only beside another arm and never sets the bit alone | Any resetprop-based property sanitizer; all of these are ordinary properties |
| SIGNATURE | signing cert SHA-256 against a build-time digest, fail-closed | Yes | Works; compiled out in debug and when no digest is supplied | Signature-spoofing frameworks that swap the PackageInfo CREATOR |
| PROP_SPOOF | fingerprint vs brand, production-claim vs build type and tags, property read latency, board vs SoC, a `/dev/__properties__` area mapped private rather than shared, an area holding allocated space its own trie can no longer reach, a property name out of order in the trie level that indexes it, a property name that disagrees with the trie path reaching it, and an `android.os.Build` constant that no longer matches the live property it was read from | Yes | Directional, only fires when the scalars claim a clean production build. The mapping arm is the one that does not depend on what the scalars say: bionic passes `MAP_SHARED` in `map_fd_ro`, `map_prop_area_rw` and the property-info parser, byte identical from `android10-release` to the current tree, and `fork` carries sharing across the zygote, so every property area on a stock device reads `s`. Measured silent on four devices: 14 areas on a Pixel 7a, 15 on an SM-G780G, 14 on a moto g04 and 68 in the app process on an SM-A065F, 111 areas and not one of them private. The arm is also the reason reasons 801 to 805 now reach a report at all; before 3.1 the walk ended at its first finding with a bare `return true`, so the flag lit with nothing to say. The accounting arm added in 3.2 is the one that reads the area's contents rather than its mapping flags, and it is the first arm in this file to ship with a positive witness as well as a negative one: it fires on an SM-A065F running Magisk 30.6 and is silent on an API 30 emulator. See the section on it below | Global, self-consistent property rewriting. For the mapping arm specifically, a virtualizer that gives up the private page and goes back to hooking reads, which puts it back in front of the latency arm. An app-cloning or container host that re-maps the property area for its guests would read `p` and would be reported; that is environment manipulation rather than a stock device, but it is a real false positive vector and is not gated. For the accounting arm, `resetprop --compact` rebuilds the area and erases the evidence completely: a compacted area is byte for byte identical to one where the property was never set, so that arm now reads only a stack on Magisk v30.7 or older, or one without PlayIntegrityFork, and no contents-reading arm can replace it. The two trie-invariant arms are the part compaction does not hide, and they are bounded in the other direction: 808 needs a same-length neighbour to pin the edited node's slot, which only 48.3% of properties have, and 809 is defeated by rewriting both copies of the name consistently. See the two sections on them below. 810 is defeated by any rewrite that lands before zygote reads the properties; see its section |
| CANARY_FP | global Pixel Canary build id, vendor fingerprint mismatch, brand cross-check | Yes | Only catches global fingerprint spoofing | Zygisk-scoped spoofing, which never reaches our process |
| CODE_INTEGRITY | libc prologue inline-hook decode (arm64-v8a and x86_64 only), executable mappings from unrecognised sources, PLT GOT slots pointing outside any recognised code source, libc text against the file on disk | Yes | Reads only this process's own address space, so no privilege is involved. Measured silent on a clean API 34 emulator and on a rooted Samsung A06: Magisk's root is filesystem-level and inline-hooks nothing in our process, so silence there is the correct answer rather than a dead check. The arms are proven to fire by the native self test, which synthesises arm64 and x86_64 trampolines and maps an anonymous executable page on every device the suite runs on. The kernel's own executable pages are allowlisted by name: `[vdso]`, `[vectors]`, `[sigpage]`, and since 2026-11-12 `[vsyscall]`, which every x86_64 kernel lists as `--xp` in every process, and `[uprobes]`. Before that, 1002 fired on every x86_64 image; the suite had only run on arm64 | A hider that hooks nothing in our address space is invisible to it, by construction. On armeabi-v7a and x86 the prologue arm does not run at all: only arm64-v8a and x86_64 have decoders, and the other two report nothing rather than guess at byte patterns nobody verified. The text comparison is corroboration only and never fires alone, because a hider that can patch a prologue can also redirect a read of the library file. The GOT arm reads at most 8000 PLT slots per loaded object and 250000 across the walk; before 2026-11-12 the 8000 was one budget for the whole walk, spent on the first system libraries in load order, so a PLT hook in this app's own library or anything loaded later was never examined. A debug build logs the slots and objects seen per scan; no device count has been read yet. The code-source allowlist that 1001, 1002 and 1003 share matches some names anywhere in the mapping path: any mapping whose name contains `jit-cache` (or `jit-zygote`, or `[anon:dalvik-`) passes, so a hooker that names its memfd `jit-cache`, as Zygisk Next and ReZygisk do, is not seen by any of the three. Anchoring those names needs witnesses of ART's own mappings on real devices, which we do not have yet. `/data/local/tmp/` was on the allowlist until 2026-11-12 with no recorded reason; it is shell writable and is where frida-server and its agent are usually pushed, so it is now foreign. `/data/data/` and `/data/user/` stay recognised, so an injector that drops its library into this app's own data directory is not seen either |
| TREAT_WHEEL | maps needle | Yes | In-process, genuinely fires | A renamed build |
| ATTEST_ANOMALY | chain signatures, CA issuers, root anchoring, challenge echo, RootOfTrust vs structural root hiding (901, 902, 903, 905, never the 904 mapping count), boot properties vs RootOfTrust when the native engine reported | Yes | Fires on the SM-A065F as reason 1206: a module rewrites `ro.boot.verifiedbootstate` to green and `ro.boot.flash.locked` to 1, so reasons 501 and 504 go correctly silent, and the spoof then contradicts the genuine hardware root of trust. The cross-check catches exactly what the property arm loses. Each of the six arms got a reason code, 1201 to 1206, in that round: until then the bit lit this row with no line under it, because the other bits this probe sets name themselves through the verdict objects and this one had none. See the section on it below. Root anchoring no longer convicts every chain it cannot anchor: a hardware chain that verifies end to end and ends in a self-signed root this build does not recognise is reported as unverifiable and sets nothing, so a new Google root or an OEM's own root is not called a forgery. See the section on that below | A keystore simulator that also sanitizes the properties it contradicts. A simulator that signs its chain up to a self-signed root of its own invention now lands on the unverifiable row rather than on this bit, which is the price of not convicting a root nobody here has seen |
| ATTEST_FORGERY | attest-key provocation, auth-bound SHA-512 provocation, self-signed single cert (each provocation arm names itself with a code from 1114 to 1124), plus two keystore boundary probes: a key generated with no attestation challenge, and a challenge one byte past the documented 128 byte maximum, plus the identifier probe: an ordinary attestation record that carries a device identifier nothing asked for, a record carrying an identifier this app cannot request at all, and a device-properties request that is accepted and then attests nothing or attests identifiers the secure environment did not vouch for, plus the StrongBox cross-check: an ordinary key the keystore labels StrongBox, or a record claiming StrongBox, after keystore2 has already said it has no StrongBox instance, and a StrongBox key served on a device whose own feature list declares no StrongBox, and a secure element that accepts a 192 bit AES key, plus the companion algorithm cross-check: a hardware-backed, Google-rooted EC chain beside an RSA chain from the same keystore that ends in an instance of an AOSP software attestation root | Yes | Works. The tag-503 arm now fires on nothing current and is retained only for TEESimulator v3 and older. The boundary arms are silent on both bench devices, which is the documented answer: a no-challenge key comes back self-signed with no record, and a 129 byte challenge draws INVALID_INPUT_LENGTH. Both are quoted from the KeyMint HAL, and both are answered by KeyMint rather than by the framework, so they reach the layer a simulator replaces. Quoted from the KeyMint HAL is also where the length arm stops: the 128 byte limit is stated only by KeyMint's Tag.aidl, and the Keymaster 3.0, 4.0 and 4.1 HALs describe ATTESTATION_CHALLENGE with no length at all. So reasons 1103 and 1104 are judged only when the legal 128 byte request was served and its own record carries attestation version 100 or higher, and a Keymaster-era TA that accepts 129 bytes, which is following its own contract, is not reported. This is the same shape as the AES 192 arm below, a rule from one generation's HAL applied to every generation, closed before a genuine device was caught by it. Measured on 2026-11-12, a retail SM-G780G, Keymaster 4.0 behind keystore2, also refuses a 129 byte challenge. The gate stays anyway, because one vendor is not a generation. Reason 1104 is gated together with 1103, and that has a cost: a simulator that claims a pre-KeyMint attestation version in its own record is judged by neither. The identifier arms are silent on both bench devices for the same kind of reason: an ordinary record carries no identifier tag at all, and the device-properties request is refused with CANNOT_ATTEST_IDS, which Tag.aidl requires from a device that cannot attest its identifiers. The accepted path is now witnessed too, on the phone station rather than the local bench, and on two vendors rather than one. A Pixel 7a and a moto g04, both declaring `android.software.device_id_attestation`, accept the device-properties request and each return tags 710, 711, 712, 716 and 717, brand, device, product, manufacturer and model, in the **hardwareEnforced** list at TrustedEnvironment level, with an empty softwareEnforced list and no privileged identifier. The two agree on every field while differing in silicon, vendor and KeyMint version, 300 against 200, so the shape the arms expect is not one implementation's habit. All three arms that judge an acceptance are therefore silent on genuine devices that perform the attestation, which is what they could not previously be checked against. The StrongBox arms are silent on all five devices measured. On the two with no secure element, a Samsung SM-A065F TEE and the AOSP emulator, the StrongBox request is refused with `StrongBoxUnavailableException` and nothing else comes back labelled StrongBox. On the three from the phone station the served path is witnessed as well: a Pixel 7a at `strongbox_keystore=300` and a Samsung SM-G780G at `strongbox_keystore=4` both declare StrongBox and serve it, so the undeclared arm stays silent, and a moto g04 declares none and refuses. That refusal is a platform answer rather than a framework one, which is the whole reason the arm is worth having: keystore2's `get_security_level` returns `HARDWARE_TYPE_UNAVAILABLE` when no KeyMint instance is registered at that level, `AndroidKeyStoreKeyPairGeneratorSpi` maps that one error to `StrongBoxUnavailableException`, and there is no `hasSystemFeature` test anywhere in the generate path. Both claim arms and the served-and-honest row are therefore hardware-witnessed. The AES 192 arm is the constraint half and is witnessed on both sides of its own gate, which is the only reason it ships: the Pixel 7a, a KeyMint 300 secure element, **refuses** the 192 bit key exactly as `IKeyMintDevice.aidl` requires, and the SM-G780G, a Keymaster 4.0 secure element at feature version 4, **accepts** it. The second measurement is why the arm is gated on the StrongBox generation: see the entry below. Ungated, this check reported a stock, locked, green-boot retail handset, which is the exact failure this file exists to catch. The companion algorithm arm is silent on four devices spanning three keystore generations. On the SM-A065F, the only one that opens its gate, the EC and RSA chains are identical above the leaf and both end in Key Attestation CA1. On the three emulator images the gate closes before the RSA key is requested at all, which is both the correct answer and the cost guard. The arm's own false positive vector was found and designed out before it shipped rather than after, which is a first for this file: see the section below | Simulators that honour setAttestKeyAlias and auth-bound keys. A simulator that fills the identifier block unconditionally, which is what forging device-properties attestation takes. The known false positive vector mirrors the over-limit one: the Tag.aidl sentence that identifier tags "must be set only when requesting attestation of the device's identifiers" is addressed to the caller, so an OEM KeyMint that populates the identifier block unprompted would be reported. The privileged half carries no such risk, because an app without READ_PRIVILEGED_PHONE_STATE receiving an attested serial or IMEI is a platform violation on any reading. For the boundary arms, a simulator that reproduces both behaviours exactly. The known false positive vector is an OEM KeyMint that accepts an over-limit challenge: Tag.aidl says INVALID_INPUT_LENGTH "should" be returned rather than must, so a non-conformant implementation would be reported. A Keymaster TA that accepts one is not a vector, because the arm says nothing below attestation version 100. For the StrongBox arms, a simulator that registers a fake StrongBox KeyMint instance, or a forged record copied from a leaked StrongBox keybox onto a device with no secure element. The two arms that need keystore2 to have denied StrongBox carry no false positive vector at all, because a device claiming a part it has just said it does not have has contradicted itself whatever any document says. The third arm does carry one: it reads the feature list as the authority on whether the hardware is there, which is what CTS does, so an OEM that ships the StrongBox HAL instance and omits the feature entry would be reported. The AES 192 arm's residual vector is a KeyMint secure element that supports 192 anyway, which its own HAL forbids in the exclusive form ("must only support 128 and 256-bit keys"). The pre-KeyMint case is no longer a vector but a measured fact, and is gated out rather than disclosed. For the companion algorithm arm, a software KeyMint that refuses to serve an attested RSA key at all, which reads as could-not-tell and sets nothing, or one that ships a complete RSA entry in its keybox so the fallback never runs. The residual false positive vector is a genuine device whose EC chain anchors to a pinned Google root while its RSA chain ends in an AOSP software root, which would require the device to hold a factory keybox for one algorithm and nothing for the other. No device measured does this, and a pre-RKP factory keybox has not been asked |
| ATTEST_REVOKED | chain serials against Google's published revocation list, offline snapshot plus optional online refresh. Informational only: sets no detection bit | Yes | See the section below | A keybox not yet published as revoked, which is the normal case for a fresh rotation |
| ATTEST_CROSS_SOURCE | attested osPatchLevel NEWER than `ro.build.version.security_patch`, which is ungated because CTS forbids it in every configuration; the two levels DISAGREEING in either direction, behind a locked-and-verified gate plus a Keymaster 4 gate; the attested verifiedBootHash differing from `ro.boot.vbmeta.digest` when both are real 32-byte digests. Six arms are computed and reported but do NOT drive the verdict: both vendor-patch arms, the absent boot patch level, a month-precision day field, a day-precision tag whose day is 00 (the HAL permits it), and an attested boot hash carrying no usable digest | Yes | Silent on all three. The OS comparison resolves real-to-real on each (202412, 202409, 202508). The boot-hash arm drives the verdict on the strength of three vendors agreeing plus the VTS assertion, rather than one device family | A simulator that also rewrites the properties in the same pass, or scopes its spoof to other packages so our process is served the genuine record |
| ATTEST_SOFTWARE | software-level attestation on a device presenting as production hardware with a declared hardware-backed keystore | Yes | Silent on the test device, whose chain is TrustedEnvironment and Google anchored | Presenting honestly as an emulator, which is also the legitimate case |
| ATTEST_VALIDITY | Issuer certificate validity windows. An inverted or zero-width window is the only finding. Expiry, a clock behind the derived floor, and a recent lapse are reported and set no bit | Yes | Silent on all three. The moto g04 reports CLOCK_BEHIND, which is correct: its clock is thirteen months behind, and that is exactly the state in which a genuine device serves a lapsed certificate. That outcome renders as not observable rather than as a review item, because a wrong device clock is a condition of the device and two of the three test handsets have one. Expiry is judged against a floor built only from witnesses that cannot be later than now (issuer notBefore, the newest embedded root, attested and system patch months), never from the device clock | Nothing: expiry is not a finding here by design. Google's own attestation guidance tells verifiers to trust chains to the published roots regardless of validity period, and batch certificates are shared across a production run |
| ATTEST_VERSION | Attested schema and KeyMint versions against the most this platform can emit, from each release's frozen KeyMint AIDL, and against the device's own hardware_keystore feature declaration. Row identity only; nothing sets this bit | Yes | Silent on all three: each sits at or below its bound (300/300 at SDK 35, schema 3 and Keymaster 4.0 at SDK 33, 200/200 at SDK 34). The Samsung declares feature version 4, which is not a centennial KeyMint version, so the declared-HAL arm correctly skips it | Nothing to defeat. The named adversary moved this field in the LOW direction, which a high-side comparison cannot catch, and a vendor TA update past the system image's own release makes a genuine device read as ahead of its bound |
| ATTEST_SHAPE | A known schema tag repeated WITHIN one authorization list, a tag the schema never attests, and a tag in the list it cannot belong to. Tag ORDER is reported in the row detail only, with no bit and no badge | Yes | Silent on all three, which emit identical ascending hardware-enforced lists `[1,2,3,5,10,503,702,704,705,706,718,719]` and software lists `[701,709]` | Emit a well-formed list, which every current stack does. Order is not usable: a genuine retail Motorola Edge (2022) emits a descending list and passes Google's own verifier |
| ATTEST_MODULE_HASH | Attested moduleHash (tag 724) against the hash the platform reports for its own module set. Row identity only; nothing sets this bit | Needs Android 16 and a KeyMint 4.0 vendor HAL; unverified, because no device in this population has either | Not applicable on all three: none reports KeyMint 4.0 (version 400), so none carries tag 724, and the platform read returns nothing below SDK 36. The comparison has therefore never executed on any device available to this project | A mismatch cannot convict in either direction: the TA pins the hash for its session, so a userspace reboot applying a staged mainline update leaves the platform ahead of the record on a genuine device |
| PIF, TRICKYSTORE, PIF_STREAM, TSEE, PIF_RUST | module directories and config files under /data/adb, companion sockets | **No** | /data/adb is SELinux-denied to untrusted_app. Retained for privileged runs, rendered NOT OBSERVABLE in the UI and excluded from the observable count | Not applicable; these cannot fire on a normal install |

## Keybox revocation, and what a pass means

The check compares every certificate serial in the attestation chain against
Google's published revocation list, using a bundled offline snapshot and, when
enabled, a live refresh.

**No revocation outcome sets a detection bit.** The published list revokes
attestation batch keys, and a batch key is shared by every handset in the
production run it was provisioned into, so a leaked keybox carries the same
serial on a spoofer's chain and on a stock, never-rooted phone from that batch.
26 of the current entries are additionally reason SOFTWARE_FLAW, which says the
device implementation is defective rather than that anyone is spoofing. Marking
those devices would be a permanent false positive their owner could not clear,
so the outcome is reported on its own row and left for the user to weigh.

Five outcomes, four of which the UI can show:

- **VERIFIED**: the serials are not on the list. This means *not known-bad*. It
  is not proof the keybox is genuine.
- **REPORTED** (KNOWN_REVOKED): a serial is on the list. Rendered amber, counted as
  neither a pass nor a detection, with the batch-key caveat stated on the row.
- **UNVERIFIED** (UNVERIFIABLE): neither the snapshot nor the network could be
  consulted. Neither a pass nor a detection.
- **UNVERIFIED** (NOT_APPLICABLE): there was no Google-anchored chain, so there
  was nothing to look up. Renders as NOT OBSERVABLE, with its own row text.
- **UNVERIFIED** (NOT_EVALUATED): an earlier trust gate failed, so the chain was
  never examined. Distinct from NOT_APPLICABLE, which asserts something about
  anchoring that those gates have not established.

What it cannot catch: Google publishes a revocation some time after a keybox is
known to be compromised. The orchestration modules on the bypass side keep their
own internal lists and mark a keybox bad well before its serial appears in the
public feed, so a freshly rotated keybox is routinely absent from it. Revocation
is a floor, not a verdict.

Pinned trust anchors are skipped before the lookup. A revoked root would be a
fleet-wide CA event rather than evidence about one device, and including it
would flag every honest user at once. The skip is decided by public key, not by
encoded bytes: Google issues one attestation key as four certificates with
different windows, and a handset keeps serving whichever instance it was
provisioned with, so a byte comparison skipped only the instance this build
happens to embed. All five published roots are now pinned, which makes the byte
comparison complete as of this build; the key comparison is what keeps it
correct when Google issues a sixth.

Snapshot cadence: regenerated by `tools/revocation/refresh_snapshot.py`, which
refuses to write on a short, malformed, or anomalously shrinking list.

## Boundary probes that were specced and not built

Four more request shapes were specced for the boundary probe. None shipped, and
the reasons are worth keeping so they are not re-proposed.

- **The 0x8001 byte single update.** It flagged a genuine handset whose OEM
  keystore mis-sizes the buffer. That is a defect in that device, not evidence
  about spoofing.
- **updateAad on a signing operation, and update after abort.** Neither is
  reachable through public API, which is checkable rather than asserted:
  `java.security.Signature` publishes four `update` overloads and no
  `updateAAD` and no `abort`, and `SignatureSpi` likewise. `Cipher.updateAAD`
  exists but belongs to a cipher operation, not a signing one. Both would need
  the keystore2 operation interface, so probing them would mean reflecting into
  non-public internals that move between releases.
- **A unique ID request.** `setUniqueIdIncluded` is `@hide`, `@TestApi` and
  `@UnsupportedAppUsage`, so it is a system-app call and the hidden API
  denylist blocks reflection at it.
- **An attestation challenge on a symmetric key.** `KeyGenParameterSpec`'s
  javadoc states that `generateKey()` throws `InvalidAlgorithmParameterException`
  in this case. Measured behaviour contradicts it: on API 34 both a Samsung TEE
  and the AOSP software keystore accepted the request with no exception at all.
  Implementing the documented rule would have flagged every device including a
  stock emulator, so the arm was dropped rather than shipped against a document
  nothing honours.

## Identifier attestation arms that were specced and not built

The spec for device-properties attestation had an arm that compared the attested
values against `Build.BRAND` and friends. It did not ship, and neither did three
smaller ones.

- **Comparing the attested values against `Build.*`.** `KeyGenParameterSpec`'s
  javadoc says the attested values "should be the same as" `Build.BRAND`,
  `Build.DEVICE`, `Build.MANUFACTURER`, `Build.MODEL` and `Build.PRODUCT`, and
  `AndroidKeyStoreKeyPairGeneratorSpi` contradicts it: for each field it sends
  `Build.<X>_FOR_ATTESTATION` whenever that is neither empty nor `unknown`, and
  that field resolves through `ro.product.<x>_for_attestation` and
  `ro.product.vendor.<x>` rather than through the property `Build.<X>` reads. A
  multi-SKU or carrier-variant device can therefore attest a value that
  legitimately differs from `Build`, which is the false positive the review of
  this spec blocked on. The value the framework actually sent is not knowable
  from an app either, because every `Build.<X>_FOR_ATTESTATION` field is `@hide`
  and `@TestApi`. The properties are real rather than theoretical: the bench
  Samsung declares `ro.product.device_for_attestation`.
- **Treating a refusal as a finding on a device that declares
  `android.software.device_id_attestation`.** A genuine device refuses when its
  remotely provisioned keys are exhausted and it is offline, and permanently
  after `destroyAttestationIds()`. That is inconclusive, not evidence.
- **Gating the probe on `android.software.device_id_attestation`.** That feature
  governs the privileged identifier subset. Nothing documents it as governing
  device-properties attestation, and the javadoc for
  `setDevicePropertiesAttestationIncluded` names no feature at all, so its
  absence does not make an acceptance provably illegitimate. Gating on it would
  also have skipped the probe on every device on this bench.
- **Requesting serial, IMEI or MEID.** Those need
  `READ_PRIVILEGED_PHONE_STATE` and the hidden `setAttestationIds`, and asking
  for identifiers this app has no business holding is not something a detector
  should do. They are watched for in the answer instead.

## StrongBox arms that were specced and not built

The spec for the StrongBox cross-check put most of its weight on a second half
it called the discriminating one: a genuine secure element has to refuse things
a reimplementation will happily accept. Three of the four candidates did not
survive primary source. The fourth, AES 192, did, and it is built; what is
recorded below is why the other three are not.

- **RSA 3072 in StrongBox.** The spec's headline arm, and it is not a rule.
  `IKeyMintDevice.aidl` says "StrongBox IKeyMintDevice implementations must
  support 2048", which is a floor on what has to work, not a ceiling on what may
  be offered. A StrongBox that also supports 3072 violates nothing. Compare the
  EC wording in the same file, "StrongBox implementations must support P_256 and
  no other curves", which is exclusive and shows the RSA sentence is not.
- **A curve other than P-256, or curve 25519, in StrongBox.** Here the HAL is
  exclusive, but the request never reaches KeyMint. `checkValidKeySize` in
  `AndroidKeyStoreKeyPairGeneratorSpi` throws
  `InvalidAlgorithmParameterException` for a StrongBox EC key of any size other
  than 256, and again for curve 25519. The real framework refuses it on a
  spoofed device exactly as on a genuine one, so the arm cannot discriminate.
- **Treating a refusal as a finding.** A device that declares StrongBox and then
  fails to serve a key may be out of remotely provisioned keys with no network,
  which `ResponseCode.aidl` documents as
  `OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY`. Only claiming more than the
  device has is reported, never claiming less.
- **The keygen latency floor.** Ruled out before this pass; see the timing entry
  in docs/DETECTION.md for why no finding here rests on a clock.
- **The two security levels in one record having to match each other.** The
  review of this spec ruled it out because nothing required it, and that is now
  half wrong. From attestation version 400, `KeyCreationResult.aidl` says
  `attestationSecurityLevel` "Must match keymintSecurityLevel" and repeats the
  requirement under the other field, where the 100, 200 and 300 schemas describe
  both as "See below" and state no relationship. So the review was right for
  Android 12 through 15 and wrong for Android 16. The arm is still unbuilt: no
  attached device emits a 400 record, so the clean path cannot be witnessed even
  once, and a record forged field by field would be given two matching levels
  anyway. Both levels are read regardless, because either one naming StrongBox
  is a claim. The API 36.1 emulator that would witness it cannot be installed
  on, its data partition being at 95 per cent.

## Why the AES size arm is gated on the StrongBox generation

The arm asks a secure element to refuse a 192 bit AES key, and the sentence it
rests on is `IKeyMintDevice.aidl`'s exclusive "STRONGBOX IKeyMintDevices must
only support 128 and 256-bit keys".

That sentence exists only in the KeyMint HAL. The Keymaster 4.0 document it
replaced lists AES as "128 and 256-bit keys" with **no StrongBox clause at all**
and no mention of 192 in either direction, so it never told a secure element to
refuse the size.

The difference is not academic. Measured on the phone station:

| Device | strongbox_keystore | AES 192 in StrongBox |
|---|---|---|
| Pixel 7a (lynx) | 300 | refused |
| Samsung SM-G780G (r8q) | 4 | **accepted** |

The SM-G780G is a stock, locked, green-boot retail handset, and it is entitled
to accept the key: it implements Keymaster 4.0. Shipping this arm ungated
reported it, which is a false positive on a genuine device and precisely the
failure mode this file audits for.

So the arm is gated on the device's own `strongbox_keystore` feature version
reaching 100. PackageManager's javadoc gives the ladder as 40 and 41 for the
Keymaster generations and 100 upward for KeyMint, 100 being where hardware ECDH
and app-generated attestation keys arrive, so 100 is the first version whose HAL
carries the restriction. A device that declares no version reads as 0 and is
never judged, which is the safe direction, because the same javadoc warns the
version may be unset on anything launched before Android 12. The SM-G780G's
declared 4 is below even 40 and off the documented ladder, which does not matter
here: anything under 100 is excluded.

The feature version is an OEM-written file, so reaching 100 is not on its own
enough to name the HAL. The gate adds two more conditions. The platform must be
Android 12 (SDK 31) or later, since no earlier platform loads a KeyMint HAL.
And the declared version must be no higher than the highest KeyMint version
`VersionBounds.platformVersionBound` allows for the running SDK: 100 on SDK 31
and 32, 200 on 33, 300 on 34 and 35, 400 on 36, 500 on 37. A declaration above
what the platform can host is not a secure element whose HAL this arm can
name, so it is not judged, and an SDK the table does not know yet has no bound
and is not judged either. So 100 on SDK 31 and 300 on SDK 34 are judged, while
400 on SDK 33 is silent.

What remains unwitnessed is a second KeyMint secure element refusing the size.
One does, and the generation that does not is now excluded by measurement rather
than by argument.

## Why the companion algorithm arm is not a root-equality check

The obvious form of this arm is "the two key algorithms must end in the same
attestation root". It is wrong, and the emulators are what said so.

AOSP's software keymaster compiles in two self-signed roots, one per algorithm,
in `contexts/soft_attestation_cert.cpp` of `platform/system/keymaster`:
`kEcAttestRootCert`, SPKI `d5100c7942ef2e83`, and `kRsaAttestRootCert`, SPKI
`f2c4746f545946c1`. They are different keys. Measured:

| Image | `hardware_keystore` | EC root | RSA root | Same root |
|---|---|---|---|---|
| `Pixel3_adb_root_test_sdk30` | absent | `d5100c7942ef2e83` | `f2c4746f545946c1` | no |
| `Pixel3_malware_sdk32` | **present, 41** | `d5100c7942ef2e83` | `f2c4746f545946c1` | **no** |
| `Pixel3_malware_sdk34` | present, 300 | `d7e776dd4922638e` | `d7e776dd4922638e` | yes |
| Samsung SM-A065F (a06) | present, 100 | `3ee44512a1af2beb` | `3ee44512a1af2beb` | yes |

The API 32 row is the one that matters. It is a stock, unmodified image that
advertises `FEATURE_HARDWARE_KEYSTORE` at version 41 while serving two different
software roots, so gating root equality on that feature would not have rescued
the rule either. "One device, one attestation root" is simply not a platform
invariant.

What ships instead is a conjunction with a positive identification at both ends.
The arm fires only when the EC chain is hardware-backed AND ends in an instance
of a pinned Google root AND the RSA chain from the same keystore ends in an
instance of a named AOSP software root. The software roots are carried by
SHA-256 and are never trust anchors; a test asserts neither appears in the
pinned set.

Three outcomes are reported and set no bit: a keystore that will not serve an
attested RSA key, because it may be out of remotely provisioned keys; a root
this build does not recognise, because a root Google adds tomorrow must not read
as a forgery; and a companion chain whose own signatures do not verify, which
also closes the obvious way to make the arm fire on a stock device by appending
a software root to a chain that never signed it.

The lesson is the same one the AES size arm taught, arriving one step earlier:
find the configuration that legitimately produces the observation before letting
a rule judge it. The only reason it arrived earlier this time is that the
station was down and the emulators were all that was left.

## Why a deleted property is still readable

The property API cannot tell a deleted property from one the device never
shipped. `__system_property_get` returns the empty string for both. That is not
an oversight, it is the whole reason deletion became a technique: TEESimulator
moved from flipping `remote_provisioning.*.rkp_only` to `false` to deleting it
outright on 2026-10-19, and its own pull request gives the reasoning. A flipped
value "leaves an anomalous reading behind: a device that ships `true` now
reports `false`", while a deleted one "reads back as unset, indistinguishable
from one the device never shipped".

Through the API that is exactly true. Through the area it is not.

bionic's `prop_area` is a bump allocator. `allocate_obj` only ever moves
`bytes_used_` forward, there is no free list, and AOSP has no delete at all:
`__system_property_find`, `_get`, `_set`, `_read` and `_foreach` are the entire
public surface, and the trie is documented as written only by init. So on a
device running stock bionic, every byte below `bytes_used_` belongs to something
the trie can still reach, and a walk from the root accounts for all of them.

Magisk adds the delete the platform does not have. `prop_area::remove` detaches
the property from its trie node, memsets the `prop_info`, and when `prune` is
set, which is what `resetprop --delete` passes, walks the trie wiping any node
left with no property and no children. Nothing reclaims that space. What is left
is a run of zeroes below `bytes_used_` that nothing points at.

The arm counts those bytes. Three gates stand between the observation and a
finding:

- **The area is walked twice.** `find_property` links a new trie node before it
  allocates the `prop_info` that hangs off it, and `allocate_obj` moves
  `bytes_used_` before either is written, so a reader can catch an ordinary
  property being added and see bytes that are briefly unreachable. That window
  closes in microseconds. A deletion does not close. An area is reported only
  when both passes agree on `bytes_used_` and on the same unreachable count.
- **The unreachable bytes must all be zero.** `remove` memsets what it detaches,
  so a deletion leaves zeroes. A half written allocation does not.
- **An area close to full is skipped.** Running out of space is the one way AOSP
  itself can strand an allocation, because `traverse_trie` links the path nodes
  it creates before `new_prop_info` can fail underneath them.

The walk refuses rather than convicts on anything it cannot read exactly: a bad
magic or version, an offset outside the used region, a name with no terminator,
a `namelen` disagreeing with the string beside it, two allocations claiming one
byte, or a trie past the node budget. A vendor that patches the layout therefore
reads as unparseable and is never judged, and the self test asserts that at
least one mapped area did parse, so a layout this build has wrong shows up as a
test failure rather than as an arm quietly failing closed on every area.

### What was measured

893 areas across two images account to the byte, with one exception. Two images
is what it is: 723 of those areas come from the handset this arm was written
against, which runs Magisk with six modules installed, and the other 170 from an
emulator, which is the only genuine negative in the set. No stock retail handset
has been measured. The count is a check on the parser, not a survey of devices.

| Image | Areas parsed | Trie nodes | Properties | Unreachable bytes |
|---|---|---|---|---|
| Samsung SM-A065F, Android 14, Magisk 30.6 | 723 | 3166 | 2074 | 15500, all in one area |
| `sdk_gphone_arm64`, API 30 | 170 | 1045 | 697 | 0 |

The exception is the one context a bootloader-status spoofer targets:
`u:object_r:bootloader_prop:s0` on the SM-A065F holds 15500 unreachable bytes in
six runs, every one of them zero, against 22316 bytes used and only 42 reachable
properties. That phone runs Shamiko, whose `service.sh` rewrites
`ro.boot.verifiedbootstate`, `ro.boot.flash.locked` and
`ro.boot.vbmeta.device_state`, which is the same context. What deleted roughly a
hundred properties' worth of space there has not been identified, and this file
does not claim it has.

The mechanism, separately, is not in doubt. A controlled `resetprop` on that
phone moved the number exactly as the allocator predicts:

| Step | `bytes_used_` | Unreachable |
|---|---|---|
| Baseline, `u:object_r:debug_prop:s0` | 4652 | 0 |
| After `resetprop debug.pifd_test 12345` | 4796 | 0 |
| After `resetprop --delete debug.pifd_test` | 4796 | 144 |

144 is the sum of the two allocations that property needed: a 32 byte trie node
and a 112 byte `prop_info`. The delete returned none of it and the trie reaches
neither.

### What defeats it, and what could falsely accuse

`resetprop --compact` rebuilds the area and erases the evidence. This arm
therefore reads a module that deleted and did not tidy up. A module that
compacts afterwards is invisible to it, which is worth saying plainly rather
than discovering later.

That sentence was written when compaction was a command someone might run. It
is now the default on the mainstream stack, so the scope is worth stating
exactly. Magisk gained `-c, --compact` in `2c98b6ccf` on 2026-03-14: absent from
v30.6 and v30.7, present in v31.0 and in v31.1, which became the current stable
on 2026-10-25, one day before this arm shipped. KernelSU and APatch had it
earlier, through `5ec1cff/resetprop-rs`, whose `-c`/`--rebuild` is the same
operation. PlayIntegrityFork has called it on every boot since `28c69e63c` on
2026-06-12, whose message records that Magisk was then the only root solution
without it, and since `3a727098b` on 2026-06-25 it also compacts the one context
a property lived in immediately after deleting it, as
`resetprop -c $(resetprop -Z "$NAME")`.

So this arm now reads either a stack on Magisk v30.7 or older, or one without
PlayIntegrityFork. The SM-A065F it fires on is the first: Magisk 30.6, and no
playintegrityfix module.

There is nothing left behind to find, and that is measured rather than assumed.
On an API 34 emulator running Magisk 31.1, a property was created, deleted and
the area compacted, with the area dumped at each step:

| Step | `bytes_used_` | Unreachable | This arm |
|---|---|---|---|
| Pristine `u:object_r:debug_prop:s0` | 4944 | 0 | silent |
| After `resetprop -n debug.pifwatch.two SOMEVALUE123456` | 5116 | 0 | silent |
| After `resetprop --delete debug.pifwatch.two` | 5116 | 172 | fires |
| After `resetprop -c u:object_r:debug_prop:s0` | 4944 | 0 | silent |

The compacted area is byte for byte identical to the pristine one. Not merely
accounted the same: `cmp` reports no difference across all 131072 bytes. The
rebuild in `resetprop-rs` is careful about exactly the things that would
otherwise give it away. It collects the survivors into a `BTreeMap` keyed by
their old offsets, so they are re-inserted in the order they already had rather
than in name order; it passes each property's existing serial counter through to
the new area; and it reproduces the dirty backup area when the original had one,
which is why the 112 byte prefix is still 112. No arm that reads the area's
contents can separate that result from a device where the property was never
set, so this file does not propose one.

Two cheaper counters exist and neither needs a rebuild. The all-zero gate is one
character from being defeated: `prop_area::remove` memsets what it detaches, and
a fork that memsets `0xFF` instead leaves the same unreachable hole with this
arm refusing it, while nothing else about the area reads differently. The second
is backfilling. A hole left by a delete is the right size to hold a trie node,
so writing a plausible node into it and linking it anywhere in the trie makes
the bytes reachable and the accounting balance again.

Both are recorded here before anyone has been seen using them. The second is
also the argument against leaning harder on all-zero than this arm already does:
the gate exists to keep a half-written allocation from convicting, not because
zeroes are hard to avoid.

AOSP can produce this signature by itself in exactly one place, `new_prop_info`.
It allocates the `prop_info` first, moving `bytes_used_`, and only then
allocates the separate block a value of `PROP_VALUE_MAX` or more needs. If that
second allocation fails it returns `nullptr` with the `prop_info` allocated and
never constructed, left zeroed and unreachable. `traverse_trie` cannot do the
same: it links every node it allocates straight away, and when it fails it
allocated nothing.

The third gate bounds that path, and the bound follows from the allocator being
a bump pointer with no free list. The stranded `prop_info` is itself inside
`bytes_used_`, so the free space the detector reads is strictly less than the
value length that failed. An area with N free bytes can only hold a stranded
allocation if some read-only property on the device carried a value longer than
N bytes, and no other name may carry a value that long, because
`SystemProperties::Add` rejects it before the area is touched.

The gate refuses any area with 4096 or fewer bytes free, so accepting a finding
asserts that no read-only property value on the device exceeds 4 KB. Across the
same 893 areas exactly one property holds a long value at all,
`ro.build.version.known_codenames` at 285 bytes, and the tightest area measured
still had 107276 bytes free. The asserted bound therefore sits 14 times above
the largest value observed, and the area that carries the signature had 174164
bytes free, which would need a read-only property value of 170 KB inside a 192
KB area.

The false positive vector is a vendor whose own init deletes properties. AOSP
cannot: there is no delete in bionic at all. But the stock-bionic assumption is
not free, and the measurement above contains a warning about it. Every property
area on the SM-A065F is 196608 bytes, and bionic ships 131072 or, under
`LARGE_SYSTEM_PROPERTY_NODE`, 1048576. Samsung patched that constant, which
proves this vendor does modify the property area build. A vendor that went
further and added a delete primitive would be reported by this arm.

Two things bound that risk rather than removing it. Of the 723 areas on that
handset, 722 account to the byte, so whatever produced the one anomaly is not a
routine habit of that vendor's init. And the anomaly sits in
`bootloader_prop`, the one context a bootloader-status spoofer targets, on a
phone that is rooted and running a module which rewrites exactly those
properties.

**This arm has not been measured on a stock Samsung**, and the 15500 unreachable
bytes on the rooted one have no identified author. Attributing them, or
measuring a stock handset from the same family, is the open question, and it is
recorded as the top lead in the watch state. If a stock device is ever found to
trip this, the gate is one condition and the arm should be demoted to reported
rather than deleted.

## Why the attestation anomaly bit had nothing to say

Reasons 1201 to 1206, added because the bit fired on the bench handset and the
report could not explain it.

`DETECTION_ATTEST_ANOMALY` has six arms. Four are trust gates in
`KeyAttestationProbe` that return before anything else is read: a chain
certificate that does not verify against its issuer, one issued by something
that is not a CA, a chain that is neither software backed nor anchored to a
pinned Google root, and an attested challenge that is not the one asked for. Two
are contradictions found during the accumulate phase: an attested root of trust
claiming a verified boot while the device shows root hiding, and boot properties
claiming a locked device while the attested root of trust disagrees.

Every other bit this probe sets already names itself, because the row renders
the verdict objects (`crossSource`, `validity`, `versions`, `shape`,
`moduleHash`) in full. The anomaly bit had no such object and no reason code, so
it lit the Key Attestation row with no line under it, and `ProbeOutcome` carried
no reasons list for the runner to collect.

### What it was hiding on the bench handset

The SM-A065F reported mask `0x4186` with reasons `[201, 305, 308, 807, 901,
902]` on 2026-10-29. Today it reports `0x4186` with `[201, 305, 308, 807, 901,
902, 905, 1206]`, and the two bootloader reasons it used to give, 501 and 504,
are gone.

Nothing in the bootloader arm changed. The device did: `ro.boot.verifiedbootstate`
now reads `green` and `ro.boot.flash.locked` reads `1`, so a module on it is
rewriting those, and 501 and 504 are correctly silent. `ro.boot.vbmeta.device_state`,
`ro.boot.veritymode`, `ro.secureboot.lockstate` and `ro.warranty_bit` read empty,
which is consistent with the deletion scar reason 807 fires on in that same
`bootloader_prop` context.

Losing 501 and 504 is what produced the anomaly bit.
`propertiesClaimLocked` is computed as `DETECTION_BOOTLOADER` being clear, so
spoofing the properties sets it true, and the real hardware root of trust still
says otherwise. Reason 1206 is now that sentence. The cross-check caught exactly
what the property arm lost, which is the arrangement working, and the only thing
wrong was that it could not say so.

Measured after the change: three devices, every bit that is set has a reason that
names it, and nothing reports an unexplained bit.

### What drives 1205 and 1206

Reason 1205 used to fire whenever the ROOT_HIDER bit was set and the attested
root of trust said locked or verified. Every ROOT_HIDER arm counted, including
904, which is a count of read-write-execute anonymous mappings against what ART
explains rather than a structure anyone built. On a stock, locked, green device a
904 misfire would therefore light two rows, and the second reads like hardware
proof while adding no evidence of its own.

1205 now reads the engine's reason codes instead of its bit, and only the
structural arms drive it: 901 a tmpfs over a read-only system partition, 902 a
bind mount rooted under /adb, 903 an overlay over /system, and 905 a tmpfs named
after a root solution. 904 still lights the Root Hider row on its own. Every
ROOT_HIDER code has to be listed as structural or as heuristic, and a unit test
fails when a new one is neither, so the next 9xx arm cannot drive this reason by
default.

1206 compares boot properties claiming a locked device with a root of trust
that disagrees, and "the properties claim locked" was the bootloader bit being
clear. A null engine array, which only an allocation failure produces, also
leaves it clear, which read absence of evidence as a claim. The claim now
requires the engine to have reported at all.

## The active provocations name their arm

`ActiveAttestationProbe` used to return a bare mask, so the forgery row could
light from either provocation with no line under it, the same defect the anomaly
bit had. Each forgery arm now returns its own code and the mask is derived from
that code's row, so the bit cannot be set without a reason.

The two provocations run the same structural checks, so each has its own codes
and a report says which request exposed the chain:

| Arm | Attest-key | Auth-bound |
|---|---|---|
| single self-signed certificate | 1114 | 1119 |
| chain signature does not verify | 1115 | 1120 |
| issuer is not a CA | 1116 | 1121 |
| challenge mismatch | 1117 | 1123 |
| hardware-claiming chain not anchored, ordinary chain clean | 1118 | |
| leaf signed with the requested SHA-512 digest | | 1122 |
| record claims no user authentication was required | | 1124 |

The software-backed readout the attest-key arm can return carries no code. It
is where the key lives, not a forgery, and it lights the software row rather
than this one.

## An unrecognised root is reported, not convicted

Reason 1203 used to fire on every chain whose record did not say software and
which did not anchor to a pinned Google root. That condition is reachable on a
genuine device in two ways. Google can add an attestation root with a new key,
as Key Attestation CA1 did, and every build shipped before its PEM is added
would then call a whole remotely provisioned fleet a forgery. And non-GMS
hardware can attest to its manufacturer's own root. `CompanionAlgorithmCheck`
already stated the rule this broke: a root Google adds tomorrow must not read as
a forgery.

So the gate now splits on what the top of the chain is. It is classified with
`CompanionAlgorithmCheck.classifyRoot`, against the same pinned Google keys and
AOSP software root keys the companion arm uses. When the origin is
`UNRECOGNISED` and the top certificate is self-signed, meaning its subject equals
its issuer and it verifies under its own key, the probe returns no finding, and
the Key Attestation row reads **unverifiable**: the chain verifies, but it ends
in a root this build does not recognise, so nothing in the record was judged. A
row that something else already convicted is never softened by this.

Everything else keeps 1203 exactly as before. An AOSP software root under a
record claiming a TEE or StrongBox is a contradiction rather than an unknown. A
chain whose top is not self-signed does not end in a root at all. A chain of one
certificate is the attested key itself, never a root, so it does not qualify
either; that is a reading of "the last certificate" this file adds, because the
alternative would let a lone self-signed certificate carrying a hardware claim
pass the gate.

The active probe's own unanchored arm would convict the same observation a
second time, so it is told the passive probe already explained the chain, the
same way a passive finding already stops it.

What this costs: a simulator that signs its chain up to a self-signed root of
its own invention now produces an unverifiable row rather than a red one. That
is a review state, not a pass, and every other check in this file still runs
against it.

## A root tmpfs that shadows nothing

Reason 905, added after the detector returned a mask of zero on a device that
was plainly rooted.

The mount arm had one tmpfs rule, 901: a tmpfs whose source is not `tmpfs`,
mounted over a read-only system partition. The second half of that is what a
module does, not what a root solution does. A Magisk install with no modules
mounts its own tmpfs at `/debug_ramdisk`, which shadows nothing, so 901 has
nothing to match. Measured from inside the app process on an API 34 emulator
running Magisk 31.1 with `magiskd` live:

```
MASK=0x0 REASONS=[]
2926 2898 0:19 / /debug_ramdisk rw,relatime master:13 - tmpfs magisk rw,seclabel,mode=755
2927 2926 0:25 / /debug_ramdisk/.magisk/worker rw,relatime master:14 - tmpfs magisk rw,seclabel,mode=755
```

The engine read those two lines and reported nothing. 905 reads the source
field, which is the mounter's own choice, and Magisk's choice is this string:
`native/src/init/mount.rs` passes `Some(cstr!("magisk"))`. It is also how Magisk
finds its own mounts again when it unmounts them for a denylisted app, in
`native/src/core/mount.rs`:

```rust
if info.source == "magisk" || info.root.starts_with("/adb/modules") {
```

which is this rule and 902, written by the other side.

### Why it is a needle and not the general rule

"Any tmpfs whose source is not `tmpfs`" would also have caught this, and it was
tempting because the first measurement supported it: on all three rooted devices
every genuine tmpfs carries source `tmpfs`, ten of them per device, and the only
exceptions were the Magisk ones.

It is not shipped that way, because a measurement on three rooted devices cannot
establish what a stock device does, and "no OEM ever names a tmpfs anything
else" is the same shape of assumption that convicted a retail SM-G780G once
already. A needle asserts nothing about stock and so cannot be wrong about it.

**That caution was not hypothetical, and two unrooted images settled it.** An
API 30 userdebug emulator carries source `tmpfs` for all nine of its tmpfs
mounts, as the rooted devices do. An API 23 userdebug emulator does not:

| Device | Root | tmpfs mounts | Sources seen |
|---|---|---|---|
| SM-A065F, API 34 | Magisk 30.6 | 15 | `tmpfs` x10, `magisk` x5 |
| Emulator, API 34 | Magisk 29.0 | 12 | `tmpfs` x10, `magisk` x2 |
| Emulator, API 34 | Magisk 31.1 | 12 | `tmpfs` x10, `magisk` x2 |
| Emulator, API 30 | none | 9 | `tmpfs` x9 |
| Emulator, API 23 | none | 4 | `tmpfs` x3, **`none` x1** |

That last one is `/sys/fs/cgroup`, mounted `- tmpfs none` on an image with no
root solution on it at all. The general rule would have reported it. So "any
tmpfs whose source is not tmpfs" is not a safe rule, it is a false positive with
a witness, and 905 is a needle because of this row rather than out of caution.

The cost is that renaming the mount source defeats 905 for one line of work, and
that only Magisk's string has been read from source. The KernelSU and APatch
equivalents are unread and are not guessed at in the needle list, which is
append-only.

Widening to the general rule is no longer a candidate. The API 23 row closes it,
and the right way to extend this arm is to read the next root solution's mount
source out of its own code and add it to the needle list.

## Two invariants on the property trie, and what they cost to break

Reasons 808 and 809, added after the arm above was found to be fully evadable by
compaction. They read the same areas and the same bytes, and they are the part
compaction does not hide, because they do not depend on any byte being left
over.

A property name is stored twice. `prop_area::find_property` splits the name on
`.` and walks one trie node per segment, creating each missing one through
`find_prop_trie_node`, and the node it ends on points at a `prop_info` carrying
the whole name. So the dotted join of the segments along a property's path
equals the name in its `prop_info`. That is reason 809.

Each level of the trie is a binary search tree keyed by one segment.
`find_prop_trie_node` compares with `cmp_prop_name`, which orders by length
first and then `strncmp`, descends left on a negative answer and right on a
positive one, and only ever creates a node where that walk arrives. There is no
rebalancing and AOSP has no delete, so an in-order walk of one level yields its
segments in strictly increasing order. That is reason 808.

Neither is a fact about any particular device, which is the point. They follow
from the only code that ever builds the structure, so acting on them needs no
corpus of values some device ought to report, and it is a corpus that made a
genuine SM-G780G look guilty once already.

What breaks them is editing a name where it lies rather than going through
`find_property`. `Enginex0/resetprop-rs` documents exactly that as its hexpatch
delete: "overwrites property name bytes with realistic dictionary words instead
of detaching trie nodes. Trie structure stays intact. Serial counters
preserved." A same-length replacement leaves every allocation size and every
counter untouched, so the area still accounts to the byte and reason 807 has
nothing to say. Rewriting only the `prop_info` copy leaves the path spelling the
old name, which 809 reads. Rewriting the segment too moves the node out of the
order its level is sorted in, which 808 reads.

### What they do not catch

808 only speaks when a same-length neighbour pins the node's slot. Across the
1329 areas measured below, 51.7% of properties had no such neighbour at their
level, because 1965 of the levels hold a single node. Of the properties whose
slot is pinned, a random same-length replacement lands wrong 60.3% of the time,
which is 29.1% of all properties. So 808 reads a careless edit, not every edit.

809 is defeated by rewriting both copies consistently, which costs the
implementer one extra write. A rebuild through `resetprop -c` also satisfies
both invariants, because it re-inserts every survivor through the normal path.

These are therefore cheap invariants that raise the cost of in-place editing,
not a wall. They are worth their keep because they share the walk the arm above
already does and because their false positive risk is not a judgement call.

### What was measured

Every `/dev/__properties__` area on four devices, read as files and walked by
the engine's own `accountPropertyArea` and `auditPropertyTrie` compiled for the
host under `-fsanitize=undefined -fno-sanitize-recover=all`:

| Device | Root stack | Areas | Trie nodes | Properties | 808 | 809 |
|---|---|---|---|---|---|---|
| SM-A065F, API 34 | Magisk 30.6, ZygiskSU, Shamiko | 723 | 3196 | 2099 | 0 | 0 |
| Emulator, API 34 | Magisk 29.0, no modules | 303 | 1414 | 929 | 0 | 0 |
| Emulator, API 34 | Magisk 31.1 | 303 | 1409 | 924 | 0 | 0 |
| Emulator, API 30 | none, userdebug image | 170 | 1047 | 699 | 0 | 0 |

1499 areas, 7066 nodes, 4651 properties, not one violation of either invariant.

The API 30 row is the one that carries the negative weight: no root solution
installed, no `magiskd`, no `/debug_ramdisk`, `/data/adb` absent. It is a
userdebug AOSP image rather than a retail handset, so it is not the last word,
but it is an unmodified image and the three rooted rows are not. Running the
engine on it returns `MASK=0x14 REASONS=[305, 506]` and neither 808, 809 nor 905
is among them. The two codes it does return predate this work and are the image
being userdebug: it ships an `su` binary and reports an unlocked bootloader.

A retail stock witness is still owed and is recorded in the watch state. The
phone station's Pixel 7a, SM-G780G and moto g04 are where it comes from.

### The layout that used to refuse, and why it no longer does

An API 23 image measured alongside the others refused every area outright, and
the reason was not the one the code claimed.

It carries magic `0x504f5250` and version `0xfc6ed0ab`, byte for byte what a
modern area carries, in a single 131072 byte `/dev/__properties__` rather than a
directory of per-context files. Its root node's `children` offset is 20, so the
first real node sits directly after the root with **no dirty backup area at
all**. The version word therefore does not separate the two layouts, and the
comment in `accountPropertyArea` claiming it did was wrong.

What refused the area was the reservation itself: the walk claimed bytes 20 to
111 for a dirty backup area that is not there, reached the real node at offset
20, found two allocations claiming one byte, and refused. Safe direction, but an
overlap was doing the work rather than a version check, and the cost was that
every area on such an image refused and all three arms built on this walk said
nothing. `minSdk` is 24, so API 24 and 25 are installable and were in that hole.

The prefix is now read from the area instead of assumed. The root's `children`
offset is the first allocation the area ever made, because `find_property`
writes it when the first segment is created and `new_prop_trie_node` allocates
at `bytes_used_`, which is still the constructor's value at that moment. So 112
means the block is there and 20 means it is not. An area holding no properties
at all has `children` of 0, and then its `bytes_used_` names the layout on its
own.

One state names neither, and it is the state a deletion leaves. When
`resetprop --delete` removes the last property of an area, Magisk's prune wipes
the first-level node and stores 0 into the root's `children` while
`bytes_used_` stays where it was. If a property is added afterwards, `children`
becomes that old `bytes_used_`, which is neither 20 nor 112. Reading the layout
from the area alone refused both, so the area with the plainest scar on the
device was silent for 807, 808 and 809, and stayed silent for good once it was
refilled.

The layout belongs to the device's bionic, not to the area, so every area on one
device has the same prefix. Before any area is judged, each mapped area votes:
a root `children` of 20 or 112 votes for that value, and a `children` of 0
with a `bytes_used_` of 20 or 112 votes for that. When every voter agrees, that
value is the device-wide layout hint, and an area that cannot name its own
layout takes it, provided its `bytes_used_` is at least the prefix and its
`children` is 0 or lies between the prefix and `bytes_used_`. The bytes between
the prefix and whatever the trie reaches then count as unreachable in the normal
way, so an emptied area reports everything past the prefix and a refilled one
reports the wiped gap. When voters disagree, or none can vote, there is no hint
and such an area is refused as before. The 807 arm and the trie arm use the
same hint for a scan. Anything else is refused rather than guessed at.

Which way each possible mistake falls is worth stating, because one of them
would be a false positive rather than a refusal. Reading 112 on an area that
uses 20 collides with the first node and refuses, which is harmless. Reading 20
on an area that uses 112 would leave the real backup block unreachable and all
zero, which is a finding. That is why the prefix is taken from the layout rather
than tried and retried until something parses.

With that in place the API 23 area parses: 269 trie nodes, 185 properties,
`unreachable` of 0, reason 807 silent, and both trie invariants satisfied. The
A06's `bootloader_prop` still reports its 15500 unreachable bytes, so the one
positive witness is unaffected. Totals across five devices: 1500 areas, 7335
trie nodes, 4836 properties, zero invariant violations.

Which release added the reservation is still unmeasured, and no longer matters
much: both layouts are read.

### A coverage bug this measurement found

Running the shipped parser over those files refused one real area outright:
`u:object_r:radio_prop:s0` on the SM-A065F. Two properties there,
`ril.signal.disprssi0` and `ril.signal.disprssi1`, have `kLongFlag` set in their
serial with a long-offset field of 0, so the walk took each `prop_info` for its
own long value, saw two allocations claim one byte, and refused the area.

Neither is a long value. `kLongFlag` is bit 16, and for a mutable property that
bit belongs to the change counter: `Update` writes
`(len << 24) | ((serial + 1) & 0xffffff)`, so the counter spans bits 0 to 23 and
crosses bit 16 every 65536 writes. `ril.signal.disprssi0` has been written about
1.9 million times. The flag only means what it says on a read-only property,
which `prop_info.h` states in a comment and which holds because
`SystemProperties::Add` refuses a value of `PROP_VALUE_MAX` or more for any name
that is not `ro.*`. bionic guards its own use the same way:
`is_read_only(pi->name) && pi->is_long()`.

The parser now does too. This cost coverage rather than causing a false finding:
the arm above was silent on that area when it should have been reading it. With
the guard in place all 1329 areas parse, and the host walk's node and property
counts match an independent Python implementation exactly.

## A Build constant that outlived its property

Reason 810: a build property no longer matches the value the app runtime read
at start.

The `android.os.Build` static fields are read from system properties once,
when the runtime initialises the class, and never again. That happens in
zygote's preload, or at app fork on builds that reload the Build constants for
appcompat overrides. `ro.*` properties are write-once for init. So a field
that differs from a live read of its property means something rewrote a
read-only property after the runtime read it, which is exactly what a late
`resetprop` does. TEESimulator PR #327 writes attested values this way from the
service stage, after zygote is already up.

Eleven of the twelve pairs below appear in the table frameworks/base
`core/jni/com_android_internal_os_Zygote.cpp` uses to reload these constants,
lines 1713 to 1741. `Build.FINGERPRINT` is not in that table; it is re-derived
just after it, lines 1812 to 1817. Every pair was also checked against
`Build.java` on main and on API 24.

| Field | Property |
|---|---|
| `Build.ID` | `ro.build.id` |
| `Build.PRODUCT` | `ro.product.name` |
| `Build.DEVICE` | `ro.product.device` |
| `Build.MANUFACTURER` | `ro.product.manufacturer` |
| `Build.BRAND` | `ro.product.brand` |
| `Build.MODEL` | `ro.product.model` |
| `Build.TAGS` | `ro.build.tags` |
| `Build.TYPE` | `ro.build.type` |
| `Build.VERSION.INCREMENTAL` | `ro.build.version.incremental` |
| `Build.VERSION.RELEASE` | `ro.build.version.release` |
| `Build.VERSION.SECURITY_PATCH` | `ro.build.version.security_patch` |
| `Build.FINGERPRINT` | `ro.build.fingerprint` |

The fields are read over JNI and each property is read live without
truncation, through `__system_property_find` and
`__system_property_read_callback` (API 26+, resolved at run time because
minSdk is 24). Where only `__system_property_get` exists the value can be cut
at 91 bytes, so a 91 byte live value only has to be a prefix of the field. A
field is skipped, never reported, when its cached value is empty or Build's
own `unknown`, when the live property is empty, when either read fails, and
when either side holds a byte outside ASCII, because JNI returns modified
UTF-8 and the two spellings of one value can then differ.

### What defeats it

- A rewrite that lands before zygote reads the properties. A module that runs
  `resetprop` in post-fs-data, as most do, sets the value zygote then reads,
  so the field and the property agree.
- A zygote restart after the rewrite. The new zygote reads the rewritten
  values and every app it forks agrees with them.
- Builds that reload the Build constants at fork. On those the comparison only
  sees a rewrite made after this app's own process started.
- Rewriting the field as well as the property, by reflection inside this
  process.

### What it has been measured on

Measured on 2026-11-12, on the branch that introduced it:

- Silent on a retail SM-G780G and a retail moto g04 (verdict 0x0, no reasons,
  on both), on a rooted Pixel 7a and a rooted SM-A065F, and on API 30 and API
  34 emulators.
- Fired (0x80, reason 810) on the API 34 emulator after `ro.build.tags` was
  rewritten with `resetprop`, and went silent again once it was restored.
- `/dev/__properties__/appcompat_override` is absent on all six.

Not measured: API 24 to 29, and any build that carries the appcompat override
area. The pure comparison is covered by the native self test, which proves the
rules above.

One false positive vector remains and is written down here: something that
rewrites `android.os.Build` fields in the Java layer inside this app's process
(per-app model spoofing on some gaming ROMs, app cloners and virtual spaces)
leaves the property untouched and the field changed, which reads exactly like
a late rewrite of the property.

## Why the RKP provisioning era is not a detection

A leaked keybox is a factory keybox, and remote key provisioning issues
short-lived per-app certificates instead, so "this chain is factory-provisioned
on a device that should be RKP-only" looks like a clean discriminator. It is
not, and the reasons are structural rather than a question of effort. Recorded
here so it is not re-proposed.

- **RKP-only is a system property, not a device fact.** `is_rkp_only()` in
  keystore2's `remote_provisioning.rs` reads `remote_provisioning.tee.rkp_only`
  or `remote_provisioning.strongbox.rkp_only` and **defaults to false**. A
  property is exactly what every resetprop module rewrites, so a rule keyed on
  the era is keyed on attacker-controlled input.
- **Falling back to the factory key is working as intended.** The comment above
  `get_rkpd_attestation_key` says so in as many words: "Depending on the Android
  release, RKP may not have been mandatory for the TEE or StrongBox KM
  instances. In such cases, lookup failure for the IRPC HAL service is WAI and
  should not cause a failure. The error should be caught by the calling function
  and allow for natural fallback to the factory key." A genuine RKP-era handset
  with no network therefore serves a factory chain.
- **The caller chooses the regime, in two ways.** `get_attest_key_info` in
  `attestation_key_utils.rs` selects an RKP key only when an attestation
  challenge is present and `Tag::DEVICE_UNIQUE_ATTESTATION` is absent, with the
  comment "Do not select an RKP key if DEVICE_UNIQUE_ATTESTATION is present".
  `get_rkpd_attestation_key_and_certs` additionally returns nothing, and so
  falls back to the factory key, unless the key is asymmetric and its domain is
  `Domain::APP`. Which chain a device presents is thus partly a property of the
  request, not of the device.

So the only rule the chain's own structure supports is "a factory-shaped chain
is suspicious", and a genuine device produces one in at least three documented
situations. Any threshold would flag real handsets, which is the bar this file
exists to enforce. The bench observation that the Pixel 7a and moto g04 present
short-lived leaves under Droid CA3 while the Samsung presents ten-year
certificates under the RSA root is real and reproducible, and it is a readout
about provisioning history rather than evidence about honesty.

What covers the actual threat instead is already shipped and does not depend on
the era: every certificate's serial is checked against Google's revocation list
in both encodings, the chain is anchored by public key to the five published
Google roots, and every issuer in the chain has to be a real CA. A leaked keybox
is caught by being revoked, not by being old.

## Notes on best-effort checks

The root-manager package probe is best-effort by construction. KernelSU, SukiSU
Ultra and ReSukiSU all let the manager package name be set at build time, so a
miss is expected rather than a bug. The probe covers the default names only.

The library needles in /proc/self/maps (the Zygisk, TrickyStore and Frida
agent names, reasons 301 and 205 among them) are matched against the line with
the random directories of an app install removed. On API 30+ an app sits at
`/data/app/~~<22 chars>==/<pkg>-<22 chars>==/`, both suffixes fresh base64url
on every install and update, so a four letter needle such as `lspd` occurs in
them by chance, about 2.3e-6 per install event. Every directory component
under `/data/app/` that ends in `==` is dropped before matching, while the file
name and every path outside `/data/app/` are kept, so `liblspd.so` still fires
wherever it is installed. A hooker that names only its install directory, and
not its library, is not seen by these needles; adoptable storage paths under
`/mnt/expand/` are not stripped and keep the old, unlikely exposure.

## Measured behaviour on a properly hidden device

The interesting case is not a carelessly rooted phone, it is one configured the
way current community guides describe. On the test device with the detector
added to the Magisk denylist, so Shamiko cleans its namespace, and with no
keystore spoofing module installed:

- The app's own mount table drops from 1479 lines to 162. Every mount rule goes
  silent: the tmpfs-over-system-partition candidates fall from 7 to 0, and the
  /adb bind that leaks a module name disappears. All remaining tmpfs mounts
  carry the genuine source "tmpfs".
- The whole native scan returns 0. Zygisk, Root Hider, property and artifact
  checks all report clean. CODE_INTEGRITY is the answer to this row, and it is an
  honest partial one: it verifies code rather than names, so a rename does not defeat
  it (with one exception: a mapping named `jit-cache` passes the code-source
  allowlist, see the CODE_INTEGRITY row), but it only sees a hider that actually touches this process. Shamiko cleaning a
  namespace leaves no hook behind, so it stays silent here too. What it covers is the
  injection case, not the mount-hiding case.
- Key attestation still fires. The properties claim verifiedbootstate=green and
  flash.locked=1, while the genuine TEE attests a bootloader that is necessarily
  unlocked, and a root hider cannot reach what the TEE signs.

That is the whole argument for treating attestation as the load-bearing
unprivileged signal and the artifact checks as corroboration: against a
configured setup, the artifact checks contribute nothing and the attestation
contradiction contributes everything.

## Method

Every detection change is validated against two classes of device: genuine
hardware that must stay clean, and a configured bypass stack that must be
caught. A check that flags a genuine device is a bug and does not ship, per
SKILLS.md.

## Why six arms are computed but never flag

`ro.vendor.build.security_patch` is `vendor_security_patch_level_prop`, which
AOSP's sepolicy grants to `vendor_init`, `keystore` and `shell` only, while
`ro.build.version.security_patch` is `build_prop` and readable by every domain.
Measurement shows that is not the whole story: the app reads the vendor value as
empty on the Pixel 7a and the moto g04, and as `2024-09-01` on the Samsung,
whose vendor policy adds the grant AOSP does not. So the arm is live on some
vendors and dead on others, through no property of the device being examined. A
finding that fires on one vendor and cannot fire on another is not a finding, so
both vendor arms report only.

The absent-boot-patch arm is held for the opposite reason: all three devices
carry tag 719, so nothing in this population can show what a genuine device
missing it looks like. VTS requires the tag by default but ships a
`--skip_boot_pl_check` escape, so absence stays a readout until a device
without it is observed.

The month-precision arm is held because an OEM that tracks a partition at month
granularity is non-conforming rather than dishonest.

The day-zero arm, a real year and month with a day of 00, used to be a finding.
The argument was that AOSP's GetPatchlevel cannot produce it, because its
property regex requires a real day. That covers the property path only. The
boot and vendor levels can reach the TA from the bootloader, which is vendor
code, and the HAL permits the shape outright. Keymaster 4.0 `types.hal` (line
805) and KeyMint `Tag.aidl` (line 817) both say of BOOT_PATCHLEVEL: "If the day
is not known, 00 may be substituted." A boot image header's `os_patch_level`
carries only a year and a month, so a bootloader that passes it on produces
this value on a genuine device. The arm now reports in the row detail.

An attested boot hash that is all zeroes or not 32 bytes long reports rather
than flags. An earlier revision called it a contradiction, since
`ro.boot.vbmeta.digest` is readable by every SELinux domain and a conforming
implementation has no excuse. No measurement was available to show a genuine
device cannot produce it, so it was walked back.
