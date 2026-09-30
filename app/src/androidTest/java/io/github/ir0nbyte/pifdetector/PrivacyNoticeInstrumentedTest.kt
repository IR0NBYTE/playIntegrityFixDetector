package io.github.ir0nbyte.pifdetector

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Covers the first-run notice for the optional online revocation refresh. The
 * offline check always runs and is not gated by this dialog.
 */
@RunWith(AndroidJUnit4::class)
class PrivacyNoticeInstrumentedTest {

    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun prefs() =
        context.getSharedPreferences("pifd_settings", Context.MODE_PRIVATE)

    @Before
    fun clearFirstRunState() {
        prefs().edit().clear().commit()
    }

    @After
    fun restoreState() {
        prefs().edit().putBoolean("privacy_notice_shown", true).commit()
    }

    @Test
    fun noticeIsShownOnFirstRun() {
        ActivityScenario.launch(MainActivity::class.java).use {
            onView(withText(R.string.privacy_revocation_title))
                .check(matches(isDisplayed()))
        }
    }

    @Test
    fun noticeIsNotShownOnceAcknowledged() {
        prefs().edit().putBoolean("privacy_notice_shown", true).commit()
        ActivityScenario.launch(MainActivity::class.java).use {
            // The main screen is reachable, which it would not be behind a
            // non-cancelable dialog.
            onView(androidx.test.espresso.matcher.ViewMatchers.withId(R.id.button2))
                .check(matches(isDisplayed()))
        }
    }

    @Test
    fun acknowledgingPersistsTheChoice() {
        ActivityScenario.launch(MainActivity::class.java).use {
            onView(withText(R.string.privacy_revocation_offline_only))
                .perform(androidx.test.espresso.action.ViewActions.click())
        }
        assertTrue(prefs().getBoolean("privacy_notice_shown", false))
        assertTrue(
            "choosing offline only must disable the online refresh",
            !prefs().getBoolean("revocation_online_refresh_enabled", true)
        )
    }
}
