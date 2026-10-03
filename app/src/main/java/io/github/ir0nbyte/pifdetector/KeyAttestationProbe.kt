package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

class KeyAttestationProbe {
    private val statusClient = AttestationStatusClient()

    private class AttestedKey(val chain: List<X509Certificate>, val challenge: ByteArray)

    data class ProbeOutcome(
        val mask: Int,
        val revocation: RevocationStatus,
        val crossSource: AttestationAnalysis.CrossSourceVerdict =
            AttestationAnalysis.CrossSourceVerdict.NOT_EVALUATED,
        val validity: ValidityStatus = ValidityStatus.NOT_EVALUATED,
        val versions: VersionBounds.Verdict = VersionBounds.Verdict.NOT_EVALUATED,
        val shape: RecordShape.Verdict = RecordShape.Verdict.NOT_EVALUATED,
        val moduleHash: ModuleHash.Status = ModuleHash.Status.NOT_APPLICABLE,
    )

    /**
     * The probe runs in two parts.
     *
     * The trust gates come first and return immediately, because nothing below
     * them may read fields out of a chain whose crypto or anchoring did not
     * hold. Everything after them accumulates into one mask instead of
     * returning, so a device that trips one finding still gets every other check
     * evaluated. The previous version returned on the first finding, which meant
     * revocation, sitting last, never ran on any device that tripped an earlier
     * check.
     */
    fun probe(
        nativeBitmask: Int,
        onlineRefreshEnabled: Boolean,
        context: Context,
        facts: AttestationAnalysis.DeviceFacts,
        presentation: DeviceIdentity.Presentation,
    ): ProbeOutcome {
        return try {
            val attested = generateAttestedChain() ?: return clean()
            val chain = attested.chain
            if (chain.isEmpty()) return clean()

            // Trust gates. These stay hard early returns.
            if (AttestationAnalysis.chainSignaturesBroken(chain)) return anomaly()
            if (AttestationAnalysis.chainHasNonCaIssuer(chain)) return anomaly()

            val extValue = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
                ?: return clean()

            val securityLevel = AttestationAnalysis.parseAttestationSecurityLevel(extValue)
            val softwareBacked = securityLevel == AttestationAnalysis.SECURITY_LEVEL_SOFTWARE
            val hardwareBacked =
                securityLevel == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    securityLevel == AttestationAnalysis.SECURITY_LEVEL_STRONGBOX

            val googleAnchored =
                AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            if (!softwareBacked && !googleAnchored) return anomaly()

            val challenge = AttestationAnalysis.parseAttestationChallenge(extValue)
            if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
                return anomaly()
            }

            val rot = AttestationAnalysis.parseRootOfTrust(extValue)

            // Accumulate phase. Every check below runs regardless of the others.
            var mask = 0

            // A software-level chain is legitimate on an emulator, a GSI or an
            // AOSP build. It is not legitimate on something presenting as
            // production hardware with a hardware-backed keystore.
            // Anchoring is deliberately NOT part of this condition. A
            // Google-anchored chain that also claims software level is
            // self-contradictory on genuine hardware, and requiring
            // !googleAnchored left exactly that combination in a dead zone where
            // no check ran at all.
            if (softwareBacked && DeviceIdentity.presentsAsPhysicalHardware(presentation)) {
                mask = mask or DetectionResult.DETECTION_ATTEST_SOFTWARE
            }

            // A KeyMint simulator keeps its own record consistent but does not
            // also control the device's properties.
            //
            // strictPatchEquality turns on the arms where ANY disagreement is a
            // finding rather than only an attested level that is newer. The
            // locked-and-Verified terms are what exclude the GSI class: CTS
            // relaxes os-patch-level equality on a GSI image (b/168663786,
            // KeyAttestationTest.checkSystemPatchLevel) because a newer system
            // image over an older OEM vbmeta legitimately reads as older, and a
            // GSI requires an unlocked bootloader.
            val strictPatchEquality = rot != null &&
                rot.deviceLocked &&
                rot.verifiedBootState == AttestationAnalysis.VERIFIED_BOOT_STATE_VERIFIED &&
                DeviceIdentity.presentsAsPhysicalHardware(presentation)

            // A closed gate is reported as not evaluated, never as a pass: there
            // was no hardware-backed, Google-anchored chain to compare against.
            var crossSource = AttestationAnalysis.CrossSourceVerdict.NOT_EVALUATED
            if (hardwareBacked && googleAnchored) {
                val verdict =
                    AttestationAnalysis.crossSourceMismatch(extValue, facts, strictPatchEquality)
                crossSource = verdict
                if (verdict.anyMismatch) {
                    mask = mask or DetectionResult.DETECTION_ATTEST_CROSS_SOURCE
                }
            }

            // Revocation deliberately sets no detection bit.
            //
            // The published list revokes attestation batch keys, and a batch key
            // is shared by every handset in the production run it was
            // provisioned into. A leaked keybox therefore carries the same
            // serial on a spoofer's chain and on a stock, never-rooted phone
            // from that batch, and 26 of the current entries are SOFTWARE_FLAW,
            // which says the implementation is defective rather than that
            // anyone is spoofing. Flagging on the serial alone would mark those
            // genuine devices permanently. The outcome is reported on its own
            // row instead, where the user can weigh it.
            val revocation = evaluateRevocation(chain, googleAnchored, onlineRefreshEnabled, context)

            // Judged without trusting the device clock. Only an inverted window
            // sets a bit; an expired issuer is reported with the shared-batch
            // caveat, on the same reasoning that keeps revocation off the
            // verdict.
            val validity = ChainValidity.evaluate(
                chain = chain,
                pinnedRoots = AttestationRoots.pinnedRoots,
                anchored = googleAnchored,
                hardwareBacked = hardwareBacked,
                attestedPatchYearMonths = listOf(
                    AttestationAnalysis.normalizeAttestedPatchToYearMonth(
                        AttestationAnalysis.parseHardwareEnforcedInteger(
                            extValue, AttestationAnalysis.TAG_OS_PATCH_LEVEL
                        )
                    ),
                    AttestationAnalysis.normalizeAttestedPatchToYearMonth(
                        AttestationAnalysis.parseHardwareEnforcedInteger(
                            extValue, AttestationAnalysis.TAG_BOOT_PATCH_LEVEL
                        )
                    ),
                ),
                systemPatchYearMonth = AttestationAnalysis.normalizePropertyPatchToYearMonth(
                    facts.systemSecurityPatch
                ),
                nowMillis = System.currentTimeMillis(),
            )
            if (validity.isFinding) {
                mask = mask or DetectionResult.DETECTION_ATTEST_VALIDITY
            }

            // A reimplementation has to choose a version number. The platform
            // arm catches a choice the running release cannot produce; the
            // declared-HAL arm is reported only, because a vendor feature file
            // left behind by a mid-life TA upgrade reads the same way.
            val versions = VersionBounds.evaluate(
                attestationVersion = AttestationAnalysis.parseAttestationVersion(extValue),
                keymasterVersion = AttestationAnalysis.parseKeymasterVersion(extValue),
                securityLevel = securityLevel,
                declaredKeystoreFeatureVersion = presentation.keystoreFeatureVersion,
                sdkInt = presentation.sdkInt,
                releaseBuild = presentation.releaseBuild,
                presentsAsPhysicalHardware =
                    DeviceIdentity.presentsAsPhysicalHardware(presentation),
            )
            if (versions.isFinding) {
                mask = mask or DetectionResult.DETECTION_ATTEST_VERSION
            }

            // Shapes a one-field-per-tag encoder cannot produce. Tag order is
            // carried for the readout but never flagged: measured retail
            // devices emit descending lists.
            val shape = RecordShape.evaluate(
                hardwareTags = AttestationAnalysis.hardwareEnforcedTags(extValue),
                softwareTags = AttestationAnalysis.softwareEnforcedTags(extValue),
                attestationVersion = AttestationAnalysis.parseAttestationVersion(extValue),
                hardwareBacked = hardwareBacked,
                anchored = googleAnchored,
                haveTrustAnchors = AttestationRoots.pinnedRoots.isNotEmpty(),
            )
            if (shape.isFinding) {
                mask = mask or DetectionResult.DETECTION_ATTEST_SHAPE
            }

            // Corroboration only, never a finding: a staged mainline update
            // produces the same mismatch a wrong derivation does.
            val moduleHash = ModuleHash.evaluate(
                attestedModuleHash = AttestationAnalysis.parseAttestedModuleHash(extValue),
                platformModuleInfo = PlatformModuleInfo.read(context),
                keyMintVersion = AttestationAnalysis.parseKeymasterVersion(extValue),
                hardwareBacked = hardwareBacked,
                anchored = googleAnchored,
            )

            if (AttestationAnalysis.isBootContradiction(rot, deviceTampered(nativeBitmask))) {
                mask = mask or DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val propertiesClaimLocked =
                (nativeBitmask and DetectionResult.DETECTION_BOOTLOADER) == 0
            if (hardwareBacked && googleAnchored &&
                AttestationAnalysis.bootPropertiesContradictAttestation(rot, propertiesClaimLocked)
            ) {
                mask = mask or DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            ProbeOutcome(
                mask, revocation, crossSource, validity, versions, shape, moduleHash
            )
        } catch (e: Throwable) {
            Log.w(TAG, "attestation probe failed; failing safe", e)
            clean()
        } finally {
            deleteKeyQuietly()
        }
    }

    private fun evaluateRevocation(
        chain: List<X509Certificate>,
        googleAnchored: Boolean,
        onlineRefreshEnabled: Boolean,
        context: Context,
    ): RevocationStatus {
        if (!googleAnchored) return RevocationStatus.NOT_APPLICABLE

        val serials = RevocationChecker.serialKeysForChain(chain, AttestationRoots.pinnedRoots)
        if (serials.isEmpty()) return RevocationStatus.NOT_APPLICABLE

        // The offline snapshot is loaded first so that a slow or hostile network
        // can never downgrade a snapshot-backed answer to UNVERIFIABLE.
        val snapshot = RevocationSnapshotLoader.load(context)
        val live = if (onlineRefreshEnabled) statusClient.fetchRevokedSerials() else null

        return RevocationChecker.evaluate(serials, snapshot, live)
    }

    private fun clean() = ProbeOutcome(0, RevocationStatus.NOT_EVALUATED)

    /**
     * A trust gate failed. Revocation was not looked at, which is not the same
     * as knowing the chain had no Google anchor, so the row must not claim it.
     */
    private fun anomaly() =
        ProbeOutcome(DetectionResult.DETECTION_ATTEST_ANOMALY, RevocationStatus.NOT_EVALUATED)

    private fun deviceTampered(nativeBitmask: Int): Boolean {
        return (nativeBitmask and DetectionResult.DETECTION_ROOT_HIDER) != 0
    }

    private fun generateAttestedChain(): AttestedKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)

        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        generator.generateKeyPair()

        val raw = keyStore.getCertificateChain(KEY_ALIAS) ?: return null
        return AttestedKey(raw.mapNotNull { it as? X509Certificate }, challenge)
    }

    private fun deleteKeyQuietly() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val TAG = "KeyAttestationProbe"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "pifd_attest_probe"
    }
}
