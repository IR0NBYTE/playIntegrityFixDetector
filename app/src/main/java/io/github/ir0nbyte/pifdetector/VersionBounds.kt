package io.github.ir0nbyte.pifdetector

/**
 * Compares the versions a record claims against the versions the device could
 * legitimately emit.
 *
 * Only a version HIGHER than a bound is evidence. Lower is the normal case: the
 * number comes from the vendor's KeyMint TA, which under the requirements
 * freeze stays on the release the device launched with, so a genuine Android 16
 * handset reporting KeyMint 1 is ordinary. A reimplementation, by contrast, has
 * to pick a number, and picking the device's own value is what forced
 * TEESimulator-RS to change this field twice.
 *
 * Android-free so it is unit testable on the JVM: every input arrives as a
 * parameter.
 */
object VersionBounds {

    data class VersionBound(val attestation: Int, val keyMint: Int)

    data class Verdict(
        /** The record claims a schema or TA version the platform cannot emit. */
        val aheadOfPlatform: Boolean = false,
        /** The record claims a TA version above what the device's own HAL declares. */
        val aheadOfDeclaredHal: Boolean = false,
        val attestationVersion: Int? = null,
        val keymasterVersion: Int? = null,
        val declaredHalVersion: Int = 0,
        val platformBound: VersionBound? = null,
        val evaluated: Boolean = true,
    ) {
        /**
         * Nothing here sets a detection bit, and the reason is that the arm
         * does not catch the behaviour it was built for while having a
         * plausible genuine path.
         *
         * The named adversary moved this field in the LOW direction: a
         * simulator was returning the device's own version where the platform
         * emits a higher one, and had to raise it. This check compares in the
         * HIGH direction, so it would not have caught that.
         *
         * Meanwhile the version in the record comes from the vendor
         * partition's TA while the bound is keyed on the system image's SDK, and
         * the Android 16 KeyMint 4 transition forced mid-life TA upgrades. A
         * vendor update that raises the TA past the system image's own release
         * is therefore a genuine device reading as ahead of its bound.
         *
         * Both arms are reported, which is still useful: a record claiming a
         * version its platform cannot emit is worth a reader's attention even
         * when it cannot convict.
         */
        val isFinding: Boolean get() = false

        companion object {
            val NONE = Verdict()
            val NOT_EVALUATED = Verdict(evaluated = false)
        }
    }

    /**
     * The highest attestationVersion and keymasterVersion a released platform at
     * this SDK level can legitimately emit, from each release's own frozen
     * KeyMint AIDL.
     *
     * This table is a maintenance surface. Every new SDK level has to be added
     * from that release's aidl_api freeze before the arm may speak about it;
     * until then the unknown exit keeps it silent rather than guessing, because
     * extrapolating would turn every phone on the next Android into a finding.
     */
    fun platformVersionBound(sdkInt: Int, releaseBuild: Boolean): VersionBound? {
        if (!releaseBuild) return null
        return when {
            sdkInt <= 0 -> null
            sdkInt <= 30 -> VersionBound(attestation = 4, keyMint = 41)
            sdkInt <= 32 -> VersionBound(attestation = 100, keyMint = 100)
            sdkInt == 33 -> VersionBound(attestation = 200, keyMint = 200)
            sdkInt <= 35 -> VersionBound(attestation = 300, keyMint = 300)
            sdkInt == 36 -> VersionBound(attestation = 400, keyMint = 400)
            sdkInt == 37 -> VersionBound(attestation = 500, keyMint = 500)
            else -> null
        }
    }

    /**
     * @param presentsAsPhysicalHardware gates the platform arm. A GSI or a
     *   system-only image puts an older system partition over a newer vendor
     *   partition, so the record legitimately exceeds the system image's own
     *   SDK bound. Those builds are already excluded by the virtual-device and
     *   production-identity screens this flag carries.
     */
    fun evaluate(
        attestationVersion: Int?,
        keymasterVersion: Int?,
        securityLevel: Int?,
        declaredKeystoreFeatureVersion: Int,
        sdkInt: Int,
        releaseBuild: Boolean,
        presentsAsPhysicalHardware: Boolean,
    ): Verdict {
        if (attestationVersion == null && keymasterVersion == null) return Verdict.NONE

        val bound = platformVersionBound(sdkInt, releaseBuild)
        val aheadOfPlatform = presentsAsPhysicalHardware && bound != null && (
            (attestationVersion != null && attestationVersion > bound.attestation) ||
                (keymasterVersion != null && keymasterVersion > bound.keyMint)
            )

        // Only a TrustedEnvironment record is compared against the declared
        // hardware_keystore version. StrongBox is deliberately out: neither
        // probe requests a StrongBox key, and AOSP ships no versioned
        // strongbox_keystore feature file to ground the comparison against.
        val declared =
            if (securityLevel == AttestationAnalysis.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
                declaredKeystoreFeatureVersion
            } else {
                0
            }
        val halComparable = declared >= 100 && declared % 100 == 0

        // keymasterVersion only. CTS binds the feature version to that field;
        // attestationVersion is the record schema version and a genuine device
        // can emit a v400 record from a KeyMint 3 implementation.
        val aheadOfDeclaredHal = halComparable &&
            keymasterVersion != null && keymasterVersion >= 100 &&
            keymasterVersion > declared

        return Verdict(
            aheadOfPlatform = aheadOfPlatform,
            aheadOfDeclaredHal = aheadOfDeclaredHal,
            attestationVersion = attestationVersion,
            keymasterVersion = keymasterVersion,
            declaredHalVersion = declared,
            platformBound = bound,
        )
    }
}
