package io.github.ir0nbyte.pifdetector

import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.BeforeClass
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

    companion object {
        private const val POLL_INTERVAL_MS = 250L

        /**
         * The first-run privacy notice is modal and would sit over every view
         * under test. Mark it as already shown so these tests exercise the main
         * screen rather than the dialog; the dialog has its own coverage in
         * PrivacyNoticeInstrumentedTest.
         */
        @BeforeClass
        @JvmStatic
        fun dismissFirstRunNotice() {
            InstrumentationRegistry.getInstrumentation().targetContext
                .getSharedPreferences("pifd_settings", android.content.Context.MODE_PRIVATE)
                .edit()
                .putBoolean("privacy_notice_shown", true)
                .commit()
        }
    }
}
