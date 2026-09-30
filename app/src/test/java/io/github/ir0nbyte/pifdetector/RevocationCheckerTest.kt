package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class RevocationCheckerTest {

    private fun snapshot(vararg serials: String) =
        RevocationSnapshot.Snapshot("2026-09-30", serials.toSet())

    private fun keysFor(serial: BigInteger) = AttestationAnalysis.serialLookupKeys(serial)

    @Test
    fun decimalKeyedSerialInSnapshotIsRevoked() {
        val serial = BigInteger("10023936558530442420")
        val status = RevocationChecker.evaluate(
            keysFor(serial),
            snapshot("10023936558530442420"),
            null,
        )
        assertEquals(RevocationOutcome.KNOWN_REVOKED, status.outcome)
    }

    @Test
    fun hexKeyedSerialInSnapshotIsRevoked() {
        val serial = BigInteger("ffb61c8e39ac7c26684d2ed1077ddd21", 16)
        val status = RevocationChecker.evaluate(
            keysFor(serial),
            snapshot("ffb61c8e39ac7c26684d2ed1077ddd21"),
            null,
        )
        assertEquals(RevocationOutcome.KNOWN_REVOKED, status.outcome)
    }

    @Test
    fun snapshotOnlyNotListedIsVerified() {
        val status = RevocationChecker.evaluate(
            keysFor(BigInteger("1234567890123456789")),
            snapshot("10023936558530442420"),
            null,
        )
        assertEquals(RevocationOutcome.VERIFIED, status.outcome)
        assertEquals(false, status.networkConsulted)
        assertEquals("2026-09-30", status.snapshotDate)
    }

    @Test
    fun networkOnlyNotListedIsVerified() {
        val live = (0 until 600).map { "%016x".format(it) }.toSet()
        val status = RevocationChecker.evaluate(
            keysFor(BigInteger("1234567890123456789")),
            null,
            live,
        )
        assertEquals(RevocationOutcome.VERIFIED, status.outcome)
        assertEquals(null, status.snapshotDate)
        assertTrue(status.networkConsulted)
    }

    /** Regression test for the silent-pass bug: no source must never read as clean. */
    @Test
    fun noSourceIsUnverifiable() {
        val status = RevocationChecker.evaluate(
            keysFor(BigInteger("1234567890123456789")),
            null,
            null,
        )
        assertEquals(RevocationOutcome.UNVERIFIABLE, status.outcome)
    }

    @Test
    fun unusableNetworkDoesNotDowngradeSnapshotAnswer() {
        val status = RevocationChecker.evaluate(
            keysFor(BigInteger("1234567890123456789")),
            snapshot("10023936558530442420"),
            null,
        )
        assertEquals(RevocationOutcome.VERIFIED, status.outcome)
    }

    @Test
    fun liveListUnionsWithSnapshot() {
        val serial = BigInteger("777777777777777777")
        val status = RevocationChecker.evaluate(
            keysFor(serial),
            snapshot("10023936558530442420"),
            setOf("777777777777777777"),
        )
        assertEquals(RevocationOutcome.KNOWN_REVOKED, status.outcome)
    }

    /**
     * A trust anchor is present in every genuine chain. If Google ever revokes
     * one, including it here would flag every honest device at once, so the
     * pinned roots are dropped before the lookup.
     */
    @Test
    fun pinnedRootSerialsAreSkipped() {
        val roots = AttestationRoots.pinnedRoots
        assertTrue("pinned roots must parse for this test to mean anything", roots.isNotEmpty())

        val rootSerialKeys = roots.flatMap { AttestationAnalysis.serialLookupKeys(it.serialNumber) }
        val keys = RevocationChecker.serialKeysForChain(roots, roots)
        assertTrue("every pinned root serial must be dropped", keys.isEmpty())

        val status = RevocationChecker.evaluate(keys, snapshot(*rootSerialKeys.toTypedArray()), null)
        assertEquals(RevocationOutcome.VERIFIED, status.outcome)
    }

    /**
     * Pins the property that makes dual-encoding lookup safe: the decimal-form
     * and hex-form key spaces in the published list do not overlap.
     */
    @Test
    fun decimalAndHexKeySpacesDoNotCollide() {
        val decimalKey = "10023936558530442420"
        val hexKey = "ffb61c8e39ac7c26684d2ed1077ddd21"
        assertTrue(decimalKey.length in 17..20)
        assertTrue(decimalKey.all { it.isDigit() })
        assertTrue(hexKey.length in 30..32)
        assertTrue(hexKey.any { it in 'a'..'f' })

        val wideSerial = BigInteger(hexKey, 16)
        assertTrue("a 128-bit serial in decimal is longer than any decimal key",
            wideSerial.toString().length > 20)
    }
}
