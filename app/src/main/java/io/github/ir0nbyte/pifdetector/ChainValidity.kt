package io.github.ir0nbyte.pifdetector

import java.security.cert.X509Certificate
import java.util.Calendar
import java.util.GregorianCalendar
import java.util.TimeZone

/**
 * Examines the validity windows of an attestation chain's issuer certificates.
 *
 * Deliberately Android-free so it is unit testable on the JVM, and deliberately
 * clock-independent for everything except the one outcome whose whole purpose is
 * to report that the clock is behind. The device clock is attacker-controllable
 * and is legitimately wrong after a flat battery, so calling checkValidity would
 * flag genuine phones.
 *
 * Instead, a floor on true current time is derived from witnesses that each
 * cannot be later than now: a certificate cannot have been issued in the
 * future, a build cannot carry a future patch level, and the app cannot be
 * running before the newest root it embeds was issued.
 */
object ChainValidity {

    /**
     * A certificate whose window lapsed less than this before the floor is not
     * called. The floor's month-granular witnesses can overshoot true now by up
     * to a month on a Beta or quarterly build that ships before the bulletin
     * month it declares, so the margin absorbs that plus a rotation lag.
     */
    internal const val EXPIRY_MARGIN_MILLIS = 7_776_000_000L // 90 days

    internal const val CLOCK_BEHIND_TOLERANCE_MILLIS = 604_800_000L // 7 days

    /**
     * A year below this is read back as a parsing artefact rather than a real
     * date: RFC 5280 encodes years before 2050 as UTCTime, and Java maps a
     * two-digit year at or above 50 to 19YY, so a certificate legitimately
     * expiring in 2050 or later can read as 1950.
     */
    private const val MIN_PLAUSIBLE_YEAR = 1990

    private const val MILLIS_PER_DAY = 86_400_000L

    /**
     * @param anchored whether the chain terminates in a pinned root. Pass the
     *   result of chainAnchorsToPinnedRoot, which the caller has already
     *   computed; this function does not recompute trust.
     * @param nowMillis the device clock, used only to detect that it is behind
     *   the floor, never to decide that something expired.
     */
    fun evaluate(
        chain: List<X509Certificate>,
        pinnedRoots: List<X509Certificate>,
        anchored: Boolean,
        hardwareBacked: Boolean,
        attestedPatchYearMonths: List<Int?>,
        systemPatchYearMonth: Int?,
        nowMillis: Long,
    ): ValidityStatus {
        return try {
            if (chain.isEmpty()) return ValidityStatus.NOT_APPLICABLE

            // chainAnchorsToPinnedRoot answers true vacuously when the pinned
            // set is empty, which is the one configuration where this code knows
            // least. Treat it as no reference rather than as an anchored chain.
            val haveRoots = pinnedRoots.isNotEmpty()
            val issuers = issuerCertificates(chain, pinnedRoots)

            // The one clock-free arm. No certificate authority emits an
            // inverted or zero-width window, so it is a hand-built structure.
            //
            // Deliberately not gated on anchoring: a forged chain is exactly
            // the case that would fail an anchoring gate, so gating here would
            // make the arm unreachable for what it is for. It IS gated on the
            // pinned set having parsed, because without that the issuer list
            // cannot have anchors excluded from it.
            val impossible = if (!haveRoots) null else issuers.firstOrNull {
                isPlausible(it) && it.notBefore.time >= it.notAfter.time
            }
            if (impossible != null) {
                return ValidityStatus(
                    ValidityOutcome.IMPOSSIBLE_WINDOW,
                    offenderSubject = subjectOf(impossible),
                )
            }

            if (!anchored || !haveRoots || !hardwareBacked) {
                // The windows of a software or unanchored chain say nothing
                // about this device's provenance.
                return ValidityStatus.NOT_APPLICABLE
            }
            if (issuers.isEmpty()) return ValidityStatus.NOT_APPLICABLE

            val floor = timeFloor(
                issuers, pinnedRoots, attestedPatchYearMonths, systemPatchYearMonth
            ) ?: return ValidityStatus.NO_REFERENCE

            // Evaluated before the expiry arms and suppressing them: a clock
            // behind the floor is exactly the state in which a genuine device
            // serves a certificate that has lapsed by its own reckoning.
            if (nowMillis + CLOCK_BEHIND_TOLERANCE_MILLIS < floor) {
                return ValidityStatus(ValidityOutcome.CLOCK_BEHIND)
            }

            val worst = issuers.filter { isPlausible(it) }.minByOrNull { it.notAfter.time }
                ?: return ValidityStatus.NO_REFERENCE
            val lapsedAt = worst.notAfter.time
            if (lapsedAt + EXPIRY_MARGIN_MILLIS < floor) {
                return ValidityStatus(
                    ValidityOutcome.EXPIRED_ISSUER,
                    offenderSubject = subjectOf(worst),
                    daysPastFloor = (floor - lapsedAt) / MILLIS_PER_DAY,
                )
            }
            if (lapsedAt < floor) {
                return ValidityStatus(
                    ValidityOutcome.RECENTLY_EXPIRED,
                    offenderSubject = subjectOf(worst),
                )
            }
            ValidityStatus(ValidityOutcome.VERIFIED)
        } catch (_: Throwable) {
            ValidityStatus.NOT_EVALUATED
        }
    }

    /**
     * The chain's issuers, excluding trust anchors.
     *
     * Exclusion is by public key, not by encoded certificate: Google publishes
     * several root certificates that share one key, so a byte comparison would
     * leave a re-issued instance of a pinned root in the set and judge the
     * anchor's own window. Self-signed elements are dropped for the same reason.
     */
    internal fun issuerCertificates(
        chain: List<X509Certificate>,
        pinnedRoots: List<X509Certificate>,
    ): List<X509Certificate> {
        if (chain.size < 2) return emptyList()
        val anchorKeys = AttestationAnalysis.anchorKeyEncodings(pinnedRoots)
        return chain.drop(1).filter { cert ->
            val selfSigned = cert.issuerX500Principal == cert.subjectX500Principal
            !AttestationAnalysis.carriesAnchorKey(cert, anchorKeys) && !selfSigned
        }
    }

    /** The latest instant that every available witness proves has already passed. */
    internal fun timeFloor(
        issuers: List<X509Certificate>,
        pinnedRoots: List<X509Certificate>,
        attestedPatchYearMonths: List<Int?>,
        systemPatchYearMonth: Int?,
    ): Long? {
        val witnesses = ArrayList<Long>()

        // A certificate cannot have been issued in the future.
        issuers.filter { isPlausible(it) }.forEach { witnesses.add(it.notBefore.time) }

        // The app cannot be running before the newest root it ships.
        pinnedRoots.forEach { witnesses.add(it.notBefore.time) }

        // A build cannot carry a future patch level, and a spoofer has to keep
        // the attested levels current to pass at all.
        (attestedPatchYearMonths + systemPatchYearMonth).forEach { ym ->
            yearMonthToEpochMillis(ym)?.let { witnesses.add(it) }
        }

        return witnesses.maxOrNull()
    }

    /** First instant of the given YYYYMM, UTC. */
    internal fun yearMonthToEpochMillis(yearMonth: Int?): Long? {
        if (yearMonth == null) return null
        val year = yearMonth / 100
        val month = yearMonth % 100
        if (year < 2008 || year > 2099 || month !in 1..12) return null
        val cal = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        cal.clear()
        cal.set(year, month - 1, 1, 0, 0, 0)
        cal.set(Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    /**
     * Both endpoints have to read as real dates before any comparison between
     * them means anything.
     */
    private fun isPlausible(cert: X509Certificate): Boolean {
        return try {
            yearOf(cert.notBefore.time) >= MIN_PLAUSIBLE_YEAR &&
                yearOf(cert.notAfter.time) >= MIN_PLAUSIBLE_YEAR
        } catch (_: Throwable) {
            false
        }
    }

    private fun yearOf(millis: Long): Int {
        val cal = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = millis
        return cal.get(Calendar.YEAR)
    }

    private fun subjectOf(cert: X509Certificate): String? =
        runCatching { cert.subjectX500Principal.name }.getOrNull()
}
