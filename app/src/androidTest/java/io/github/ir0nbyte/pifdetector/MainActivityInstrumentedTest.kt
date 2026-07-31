package io.github.ir0nbyte.pifdetector

import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityInstrumentedTest {

    @get:Rule
    val activityRule = ActivityScenarioRule(MainActivity::class.java)

    @Test
    fun runButtonIsDisplayed() {
        onView(withId(R.id.button2))
            .check(matches(isDisplayed()))
    }

    @Test
    fun statusCardIsDisplayed() {
        onView(withId(R.id.statusCard))
            .check(matches(isDisplayed()))
    }

    @Test
    fun clickRunButtonShowsResults() {
        onView(withId(R.id.button2)).perform(click())
        awaitDisplayed(R.id.resultsRecyclerView)
    }

    /*
     * Polls instead of sleeping a fixed interval. The detection pass now
     * includes two AndroidKeyStore attestation probes, and key generation time
     * varies by an order of magnitude between a software-backed emulator and a
     * real TEE (StrongBox especially), so any single hardcoded wait is either
     * flaky on slow devices or wasted time on fast ones.
     */
    private fun awaitDisplayed(viewId: Int, timeoutMs: Long = 60_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var last: Throwable? = null
        while (System.currentTimeMillis() < deadline) {
            try {
                onView(withId(viewId)).check(matches(isDisplayed()))
                return
            } catch (t: Throwable) {
                last = t
                Thread.sleep(POLL_INTERVAL_MS)
            }
        }
        throw AssertionError("view $viewId not displayed within ${timeoutMs}ms", last)
    }

    private companion object {
        const val POLL_INTERVAL_MS = 250L
    }
}
