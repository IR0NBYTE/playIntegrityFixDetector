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

        // Wait for background execution
        Thread.sleep(3000)

        onView(withId(R.id.resultsRecyclerView))
            .check(matches(isDisplayed()))
    }
}
