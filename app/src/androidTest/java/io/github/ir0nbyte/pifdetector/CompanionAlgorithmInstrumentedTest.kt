package io.github.ir0nbyte.pifdetector

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * The companion algorithm probe against the real keystore.
 *
 * The unit tests cover the table. What they cannot cover is what this keystore
 * actually serves for two algorithms, which is the entire question. A failure
 * here says either that the device is contradicting itself or that the arm
 * rests on something this implementation does not honour, and both need a
 * person rather than a suppression.
 */
@RunWith(AndroidJUnit4::class)
class CompanionAlgorithmInstrumentedTest {

    private val probe = CompanionAlgorithmProbe()

    /**
     * The EC arm has to have run. Without a classified primary chain the probe
     * would report clean for the wrong reason.
     */
    @Test
    fun thePrimaryArmActuallyRan() {
        val observation = probe.observe()
        Log.i(TAG, "observation=$observation")

        assertTrue(
            "the EC attestation request produced no chain at all",
            observation.primaryChainLength > 0
        )
        assertTrue(
            "the primary chain was not classified",
            observation.primaryOrigin != CompanionAlgorithmCheck.RootOrigin.ABSENT
        )
    }

    /**
     * The companion request happens exactly when the table says it is worth
     * the round trip, and never otherwise. This is the cost guard.
     */
    @Test
    fun theCompanionIsRequestedOnlyWhenTheGateIsOpen() {
        val observation = probe.observe()

        assertEquals(
            "the companion request and the gate disagree",
            CompanionAlgorithmCheck.worthAsking(
                observation.primaryOrigin,
                observation.primaryHardwareBacked
            ),
            observation.companionRequested
        )
    }

    /**
     * On a device whose EC chain is hardware-backed and Google-rooted, the RSA
     * chain must come from a Google root too. A software root here is the
     * finding this arm exists for, so on genuine hardware it must be absent.
     */
    @Test
    fun aGenuineKeystoreDoesNotServeTheSoftwareFallbackForOneAlgorithm() {
        val observation = probe.observe()
        if (!observation.companionRequested) return

        assertTrue(
            "the RSA request produced no chain, so nothing was compared",
            observation.companionChainLength > 0
        )
        assertEquals(
            "this keystore served a Google-rooted EC chain beside an AOSP " +
                "software-rooted RSA chain",
            CompanionAlgorithmCheck.RootOrigin.GOOGLE_PINNED,
            observation.companionOrigin
        )
    }

    /** No device in the bench may trip this arm. */
    @Test
    fun theProbeReportsNoFindingOnThisDevice() {
        val outcome = probe.probe()
        Log.i(TAG, "verdict=${outcome.verdict} mask=${outcome.mask} reasons=${outcome.reasons}")

        assertFalse(
            "the companion algorithm arm fired on this device: ${outcome.verdict}",
            outcome.verdict.isFinding
        )
        assertEquals(0, outcome.mask)
        assertEquals(emptyList<Int>(), outcome.reasons)
    }

    /** Two attested keys per run is two keys to clean up. */
    @Test
    fun theProbeLeavesNoKeysBehind() {
        probe.probe()

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in listOf("pifd_companion_ec", "pifd_companion_rsa")) {
            assertFalse("$alias was left in the keystore", keyStore.containsAlias(alias))
        }
    }

    private companion object {
        const val TAG = "CompanionAlgoTest"
    }
}
