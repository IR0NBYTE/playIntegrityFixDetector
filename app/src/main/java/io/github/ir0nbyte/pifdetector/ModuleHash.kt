package io.github.ir0nbyte.pifdetector

import java.security.MessageDigest

/**
 * Cross-checks the attested moduleHash (tag 724, KeyMint 4.0) against the hash
 * the platform itself reports over its module set.
 *
 * This row sets no detection bit, and the reason is a timing one rather than a
 * shared-material one. The TA pins the hash for the life of its session, so a
 * userspace reboot that activates a staged mainline update leaves the platform
 * reporting the new module set while the TA still attests the one it was given
 * at boot. A bare mismatch therefore cannot distinguish a spoofer deriving the
 * value wrongly from a genuine device holding a stale but authentic one, and an
 * ambiguous observation is no evidence.
 *
 * It is still worth reporting: the tag was countered late by the simulator
 * stacks, so a matching pair is real corroboration even though a mismatch
 * cannot convict. The comparison also assumes the framework API is not itself
 * intercepted, which makes it corroboration rather than a primary signal.
 */
object ModuleHash {

    private const val SHA256_BYTES = 32

    enum class Outcome {
        /** No KeyMint 4.0 record, or the platform has no module-hash API. */
        NOT_APPLICABLE,

        /** The record or the platform value could not be read. */
        UNREADABLE,

        /** The record carries no tag 724. The tag is optional, so this is permitted. */
        ABSENT,

        /** Present but not a 32-byte digest: an encoding this code does not know. */
        MALFORMED,

        /** The attested digest equals the platform's. */
        MATCHED,

        /** They differ, which a staged module update also produces. */
        MISMATCHED,
    }

    data class Status(
        val outcome: Outcome,
        val keyMintVersion: Int? = null,
    ) {
        companion object {
            val NOT_APPLICABLE = Status(Outcome.NOT_APPLICABLE)
            val UNREADABLE = Status(Outcome.UNREADABLE)
        }
    }

    /** KeyMint 4.0, the generation that introduced the tag. */
    private const val KEYMINT_4 = 400

    /**
     * @param platformModuleInfo the raw DER module blob the platform reports, or
     *   null when the platform cannot supply one. The attested value is a
     *   SHA-256 over exactly these bytes.
     */
    fun evaluate(
        attestedModuleHash: ByteArray?,
        platformModuleInfo: ByteArray?,
        keyMintVersion: Int?,
        hardwareBacked: Boolean,
        anchored: Boolean,
    ): Status {
        if (!hardwareBacked || !anchored) return Status.NOT_APPLICABLE
        if (keyMintVersion == null || keyMintVersion < KEYMINT_4) {
            return Status(Outcome.NOT_APPLICABLE, keyMintVersion)
        }
        if (platformModuleInfo == null || platformModuleInfo.isEmpty()) {
            return Status(Outcome.NOT_APPLICABLE, keyMintVersion)
        }
        if (attestedModuleHash == null) return Status(Outcome.ABSENT, keyMintVersion)
        if (attestedModuleHash.size != SHA256_BYTES) {
            return Status(Outcome.MALFORMED, keyMintVersion)
        }

        val expected = sha256(platformModuleInfo) ?: return Status(Outcome.UNREADABLE, keyMintVersion)
        return if (attestedModuleHash.contentEquals(expected)) {
            Status(Outcome.MATCHED, keyMintVersion)
        } else {
            Status(Outcome.MISMATCHED, keyMintVersion)
        }
    }

    internal fun sha256(input: ByteArray): ByteArray? = try {
        MessageDigest.getInstance("SHA-256").digest(input)
    } catch (_: Throwable) {
        null
    }
}
