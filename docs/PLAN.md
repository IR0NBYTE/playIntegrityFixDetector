# PIF Detector plan: v2.8 to v3.1

Working plan for the whole repository: detection engine, Kotlin probes, UI, tests, CI,
docs and repo hygiene. Each phase is a set of branches that can ship on its own. Nothing
in a later phase is a prerequisite for an earlier one.

Ground rules carried over from SKILLS.md: every marker is verified against primary source
before it is added; a check that exists is not a check that fires; false positives are
bugs; restore before you delete; test on a real build before a commit; no AI traces in
anything committed.

## 0. Baseline (verified 2026-09-30)

Repository

- main is v2.7 (074f0e9, 2026-09-15). No open issues, no open PRs, no CI workflows
  (removed 2026-05-06). origin/review/v2.7-hardening is a stale pre-squash copy of the
  same commit and can be deleted.
- Working tree has 7 untracked files that do not belong to the project: five images and
  one script dropped in the root, plus two .idea files not covered by .gitignore.
- CONTRIBUTING.md still documents EXPECTED_SIG_HASH in native-lib.cpp and
  sig.hashCode(); the code pins RELEASE_CERT_SHA256 at build time. SKILLS.md lists
  84 unit tests; there are 95 unit and 9 instrumented. Its tracking list predates the
  KeyMint-simulator wave.
- Both pinned attestation roots match Google's live root list exactly (2 of 2).
  Revocation list: 1759 entries, all REVOKED (1733 KEY_COMPROMISE, 26 SOFTWARE_FLAW),
  979 decimal-keyed and 780 hex-keyed, 179 KB raw.
- Root-manager probe and manifest queries are in sync (test enforced) but miss
  com.sukisu.ultra and com.resukisu.resukisu, the two most-installed KernelSU forks.

Ecosystem, and what it did to the signal set

- chiteroman/PlayIntegrityFix and Dr-TSNG/ZygiskNext are gone from GitHub; TrickyStore is
  dead. The active stack is PlayIntegrityFork v18 or inject-s for fingerprints,
  TrickyStoreOSS, TEESimulator v4, TEESimulator-RS or OhMyKeymint for attestation,
  NeoZygisk, ReZygisk or the relicensed LSPosed/ZygiskNext for injection, and
  Integrity-Box, AlwaysStrong or specter as the orchestration layer.
- TEESimulator v4 (2026-08-11) runs AOSP's reference KeyMint TA in-process inside
  keystore2 and signs with a leaked keybox, so every field of the attestation record is
  consistent by construction. Its August PRs clamp attestationVersion to VINTF, carry
  MODULE_HASH, sync ro.boot.vbmeta.digest to the attested hash, honour auth-bound keys and
  attest-key graphs. OhMyKeymint reimplements the keystore AIDL entirely.
- TrickyStoreOSS pads forged keygen replies to the measured latency of real TEE keygen
  (2026-08-20) after Duck Detector's timing oracle caught forged attestation being faster
  than real. Non-attestation operations are forwarded to real hardware by TS-OSS,
  TEESimulator and TrickyLuke.
- GMS now detects Dobby inline hooks; PIFork moved to ShadowHook. resetprop-rs writes
  properties with init-style serials, deletes with count-preserving replacements, and
  hides its hook page in init behind memfd. Integrity-Box ships an auto-fix list of
  "known detection props" that is a superset of our BOOTLOADER probe.
- AlwaysStrong and specter auto-target every newly installed package via inotify, so a
  detector is served forged attestation from its first launch.

What fires today, unprivileged, against a configured stack

| Flag | Verdict |
|---|---|
| DEBUGGER, FRIDA | fire, but Frida only on default port and thread names |
| SIGNATURE | fires unless ApkSignatureKillerX is installed (CREATOR swap) |
| TREAT_WHEEL | fires, single needle, renamed builds evade |
| ZYGISK | neutralised by NeoZygisk and ReZygisk trace cleaning, HMA, and KSU 3.3.0's custom manager package name |
| ROOT_HIDER | mount diff reads /proc/1/mounts, which hidepid=2 denies to apps, so it fails open; overlay and rwx are cleaned by the denylist |
| BOOTLOADER | dead: exactly the props every sanitizer resets |
| PROP_SPOOF, CANARY_FP | partial: only global spoofing setups |
| ATTEST_ANOMALY | structural checks pass by construction against TEESimulator v4, OMK and TS-OSS; RoT-vs-tamper is gated on the dead ROOT_HIDER bit; props-vs-RoT is satisfied by vbmeta.digest sync; the revocation check is the only live discriminator and it is off by default and skips silently when the fetch fails |
| ATTEST_FORGERY | tag-503 dead (documented); digest tracking matched by TEESimulator-RS; attest-key provocation anchors through the keybox to a real Google root |
| PIF, PIF_STREAM, TSEE, PIF_RUST, TRICKYSTORE | privileged only, already rendered as not observable |

The conclusion the plan is built on: the durable unprivileged signals are now keybox
provenance (revocation), cross-source consistency (attestation fields against sources the
spoofer does not control together), and behaviour (timing distributions, cross-process
views). Artifact hunting stays in the engine for sloppy installs and privileged runs, but
it is not coverage.

## 1. Phases

### Phase A: v2.8, truth and hygiene

Branches: chore/repo-cleanup, docs/claims-match-code, fix/manager-ids, chore/ci.

A1. Repo cleanup. Move the five stray root files out of the tree, add .idea/deviceManager.xml
and .idea/vcs.xml to .gitignore, delete origin/review/v2.7-hardening.

A2. Make every documented claim match the code.
- README: ROOT_HIDER mount-namespace divergence and the 1b RoT-vs-tamper contradiction cannot
  fire unprivileged; say so. PIF_STREAM's "module dir without pif.json" now fires on every
  inject-s install because inject-s moved to pif.prop; relabel it. Revocation list is 1759
  entries at the time of the audit, not the 1742 the README then claimed. Frida parent-cmdline check fails open under hidepid.
- CONTRIBUTING: replace the EXPECTED_SIG_HASH section with the RELEASE_CERT_SHA256 flow,
  JDK 17, SDK 36.
- SKILLS: refresh the tracking list (TEESimulator, TEESimulator-RS, OhMyKeymint,
  AlwaysStrong, specter, NeoZygisk, LSPosed/ZygiskNext, MeowZygisk, resetprop-rs,
  Duck-Detector-Refactoring as the peer to read), test counts (95 + 9), and the removed
  projects.
- Add docs/COVERAGE.md: the per-flag audit table above, kept current with each release.

A3. Root-manager identities. Add com.sukisu.ultra and com.resukisu.resukisu to the native
list and the manifest queries (RootManagerQueriesSyncTest enforces the pairing). Note in
COVERAGE.md that KernelSU, SukiSU and ReSukiSU let the manager package be renamed at build
time, so the probe is best-effort by design.

A4. Privileged path table. Add /data/adb/Box-Brain (Integrity-Box) and /data/adb/teeforge.
Verify each against the module's install script before adding, per SKILLS section 2.

A5. CI without signing. GitHub Actions on push and PR: JDK 17, NDK, assembleDebug for all
four ABIs with warnings as errors, testDebugUnitTest, lintDebug, the AI-trace grep from
SKILLS section 7 over the diff, and a roots-drift job that fetches
android.googleapis.com/attestation/root and compares SHA-256 fingerprints with
AttestationRoots.kt. Release stays manual until a keystore secret exists.

Done when: CI is green on main, README and COVERAGE.md describe only behaviour that the
code has, and the two new manager ids are covered by the sync test.

### Phase B: v2.9, revocation as a first-class signal

Branch: feat/revocation-first-class.

B1. Default on. The toggle becomes "also refresh online", not "check at all".

B2. Bundled snapshot. Ship the revocation list as a gzipped asset (179 KB raw) with its
fetch date, loaded at probe time. A scheduled CI job regenerates it monthly and opens a PR
so it never goes stale silently. A unit test asserts the bundled snapshot parses, contains
both key encodings, and is younger than 90 days at build time.

B3. Three-state outcome. verified, revoked, unverifiable. The passive probe returns
unverifiable when the chain is Google-anchored and neither the snapshot nor the network
could be consulted; the UI renders it as a warning with the snapshot date, never as a
pass. Today the null path at KeyAttestationProbe.kt:65 is a silent pass.

B4. Revocation is reported as its own finding (reason code under ATTEST_ANOMALY, see
Phase D), so a user can tell "revoked keybox" from "chain does not anchor".

B5. Privacy. First run explains that the online refresh talks to Google; the snapshot
works with no network and no consent.

Done when: a lab device running TS-OSS or TEESimulator with a revoked keybox flags in
airplane mode; a genuine device in airplane mode shows verified against the snapshot; a
Google-anchored chain with no snapshot and no network shows unverifiable, not clean.

### Phase C: v2.9, cross-source consistency

Branch: feat/attestation-consistency.

C1. Patch level. Parse osPatchLevel (tag 706), vendorPatchLevel (718) and bootPatchLevel
(719) from the attestation extension and compare with ro.build.version.security_patch and
ro.vendor.build.security_patch, normalised to YYYYMM. TS-OSS changes attestation only, and
TEESimulator's shipped default is "today" for the system level, so both diverge from the
properties on most installs. Gate on a hardware-backed, Google-anchored chain. Validate
against the genuine corpus first: some OEMs report YYYYMMDD in one place and YYYYMM in
the other, and vendor may legitimately lag system.

C2. Verified-boot hash. Compare the attested verifiedBootHash with ro.boot.vbmeta.digest
when both are present and the chain is hardware-backed and anchored. TEESimulator syncs
the two since PR #233; TS-OSS and TrickyLuke on an unlocked device do not always. Cheap,
no known false positive on genuine hardware (AVB always emits the digest).

C3. Spike: attestationVersion against the KeyMint HAL version. Duck cross-references the
VINTF manifest. Confirm whether an untrusted app can read /vendor/etc/vintf or resolve the
declared IKeyMintDevice version some other way before writing a probe. TEESimulator clamps
this since PR #247, so the value is in TS-OSS and older simulators; ship only if the
source is readable and the corpus is clean.

C4. Spike: root generation against the device's provisioning era. Leaked keyboxes are
factory keyboxes and always chain to the legacy RSA root; TEESimulator states it cannot
re-root RKP-provisioned keys (PRs #235, #263). A chain that anchors at the RSA root on a
device that should be RKP-only is a contradiction. Needs a per-device policy
(ro.product.first_api_level, model) and corpus evidence before it becomes a check.

Done when: C1 and C2 fire on a TS-OSS default install and are silent on every genuine
device in the lab matrix; C3 and C4 have a written go or no-go with evidence.

### Phase D: v3.0, result model, report and UI

Branch: feat/result-states.

D1. Per-check state. Replace the boolean plus privilegedOnly pair with a state:
DETECTED, CLEAN, NOT_OBSERVABLE, UNVERIFIABLE, SKIPPED. The native bitmask stays the SSOT
for DETECTED bits; the Kotlin layer adds the states it alone can know (revocation
unverifiable, probe unsupported on this device).

D2. Reason codes. The native engine returns, next to the bitmask, a small array of which
sub-probe fired (which needle, which property, which path), so a detection is explainable
without a debugger. Kept as ints, mapped to strings in Kotlin.

D3. Export report. Plain-text report of every check, its state, its reason codes, the
attestation chain summary (roots, security level, patch levels, RoT), the bundled snapshot
date, and build identity. Users attach it to issues; today a screenshot is all they have.

D4. targetSdk 36 with edge-to-edge insets handled (the action bar currently draws under
the status bar and the run button under the navigation bar on API 36). Verify visually on
an API 36 image; instrumented tests do not catch overlap.

D5. Expandable rows with the reason text; NOT_OBSERVABLE and UNVERIFIABLE keep their own
colours and stay out of the pass count.

Done when: DetectionResultTest still asserts the bitmask SSOT, a report exported from a
lab device names the exact needle that fired, and the API 36 layout is correct.

### Phase E: v3.0, behavioural probes

Branch: feat/keystore-behaviour. These are the new load-bearing signals; each ships only
with corpus evidence and starts as a warning, not a danger.

E1. Timing oracle. In native, pin to one core (sched_setaffinity), generate N pairs of
attested and non-attested EC keys, interleaved, and record the distribution, not the mean:
median ratio, IQR, and direction consistency across pairs. TS-OSS pads to an EMA of the
mean, which leaves variance and skew intact. Calibrate thresholds on the genuine corpus,
publish them in COVERAGE.md, and report the raw numbers in the D3 export.

E2. Spike: cross-process attestation compare. Targeting is per calling uid. An isolated
service runs under a different uid, but isolated_app cannot reach keystore2 directly, so
the path is a keystore grant from the main process and a read through the grant, or a
second process under the same uid, which sees the same routing. Determine on a device
with TS-OSS (leaf hacked on read) and one with TEESimulator (chain forged at generation)
whether either path yields a different chain from the main process. Go or no-go in
writing.

E3. Spike: generateKey reply and authorization-list shape. keystore2 appends a
SOFTWARE-level USER_ID as the last authorization of every stored key; every AOSP KeyMint
returns CREATION_DATETIME at the KEYSTORE level. The public KeyInfo API may not expose
enough; if it needs the private keystore2 binder, decide whether hidden-API access is
acceptable for this app.

E4. Replace the dead ROOT_HIDER mount diff rather than delete it (restore before delete):
mount-id gaps and mount-root attributes from /proc/self/mountinfo, and statx mount ids
where the kernel fills them, are readable in-process and detect unmounted entries by the
holes they leave.

Done when: E1 has published thresholds and zero false positives on the corpus; E2 and E3
have a written verdict; E4 fires on a denylisted app under NeoZygisk on a lab device.

### Phase F: v3.1, engine structure and maintenance

Branches: chore/native-split, chore/deps, docs/lab-matrix.

F1. Split native-lib.cpp (1431 lines, one file) into units: strings, props, process,
mounts, artifacts, attestation-support, jni. One object library each, same CMake flags.

F2. Generate the obfuscated string table at build time from a plaintext list in the
source tree (Python step in CMake), keeping the XOR scheme. Reviewers read the plaintext,
the binary carries the encoded form, and NativeEngineInvariantsTest keeps asserting the
round trip. Today every marker is an opaque base64 literal, which is exactly how the VM
bug hid for months.

F3. Dependency bumps on their own branch: AGP, Kotlin, core-ktx, material. AGP 9 changes
the Kotlin plugin wiring; take it separately from anything that touches detection.

F4. Cadence. One ecosystem pass per month per SKILLS sections 1 to 3, with the GitHub
API as ground truth, feeding COVERAGE.md. The local scheduled-task mechanism only runs
while the desktop app is open, so this stays a manual monthly session unless it moves to
a cloud routine that only needs GitHub.

F5. docs/LAB.md: the device and setup matrix below, with the exact module versions used,
so a result can be reproduced.

## 2. Verification matrix

Every detection change is run against all of these before its commit is approved.

Genuine (must stay clean)
- Locked Pixel on stock, Android 15 or 16 (RKP-provisioned).
- Locked Samsung on stock (StrongBox present).
- Locked non-Google OEM on stock (Xiaomi or OnePlus, Qualcomm).
- Unlocked device on a custom ROM with no root: BOOTLOADER and props-vs-RoT may fire
  honestly, everything else must stay clean.
- Emulator with software attestation: anchoring exempt, must stay clean.

Configured stacks (must be caught by the signal under test)
- KernelSU or Magisk, NeoZygisk, PIFork v18, TrickyStoreOSS v3.1 with a private keybox.
- KernelSU, ReZygisk, inject-s, TEESimulator v4 patch mode.
- Magisk, ZygiskNext, AlwaysStrong (TEESimulator-RS bundle).
- Integrity-Box v43 on top of one of the above.
- Any of the above with a keybox that appears in the revocation list.

The remote phone station and the local emulators cover most rows; the RKP-only Pixel row
needs a physical device on Android 16.

Per-change checklist
1. JDK 17 build for all four ABIs, zero warnings; 95+ unit tests; instrumented tests on
   an AVD.
2. Run on every applicable matrix row; record the exported report for each.
3. AI-trace scan over the diff and the commit message (SKILLS section 7).
4. Explicit approval of the commit after the test evidence is shown.

## 3. Conventions

- Branch prefixes: feat/, fix/, perf/, docs/, chore/. One concern per branch. Never rename
  the head branch of an open PR.
- Version bump is its own commit. Release notes lead with the finding, in the project's
  voice, without AI trailers or typographic punctuation.
- A new marker enters the engine only with a link to the primary source that proves the
  string, per SKILLS section 2, and a COVERAGE.md row that says whether it can fire
  unprivileged.
- A check that cannot fire unprivileged is either replaced with one that can, or kept
  and labelled not observable. It is never counted as coverage.

## 4. Deliberately not doing

- More module-name and path needles for the privileged-only flags. They cannot fire on a
  real install and the modules rename faster than a release cycle.
- The app_zygote SELinux oracle. It is Duck's, it has a purpose-built counter
  (NoAppZygote), and the modules test against Duck first; a check Duck does not have stays
  undetected longer.
- Broad Frida coverage. This app is a PIF detector; Frida detection beyond defaults
  belongs to the YinkoShield engine.
- Any check that flags genuine hardware to catch a spoofer. False positives are bugs.

## 5. Open questions

- Can isolated_app read a granted key's certificate chain through keystore2, and does
  TS-OSS or TEESimulator treat that uid as untargeted (E2)?
- Is /vendor/etc/vintf readable by an untrusted app, or is there another route to the
  declared KeyMint HAL version (C3)?
- What is the smallest reliable rule for "this device must be RKP-provisioned" (C4)?
- Should the online revocation refresh be consent-gated on first run or simply on by
  default with the snapshot as the offline path (B5)?
