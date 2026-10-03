package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * The validity check is deliberately narrow. Google's own key-attestation
 * guidance tells verifiers to trust a chain terminating in the published roots
 * regardless of certificate validity period, so an expired issuer must never be
 * a finding. Only an inverted or zero-width window is, and recognising that
 * needs no clock.
 */
class ChainValidityTest {

    private val year2024 = 1_704_067_200_000L // 2024-01-01T00:00:00Z
    private val year2026 = 1_767_225_600_000L // 2026-01-01T00:00:00Z
    private val year2030 = 1_893_456_000_000L // 2030-01-01T00:00:00Z

    @Test
    fun invertedIssuerWindowIsTheOnlyFinding() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2030, year2024),
        )
        val s = evaluate(chain)
        assertEquals(ValidityOutcome.IMPOSSIBLE_WINDOW, s.outcome)
        assertTrue(s.isFinding)
        assertTrue(s.offenderSubject!!.contains("intermediate"))
    }

    @Test
    fun zeroWidthWindowIsAlsoImpossible() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2026, year2026),
        )
        assertEquals(ValidityOutcome.IMPOSSIBLE_WINDOW, evaluate(chain).outcome)
    }

    /**
     * An expired issuer is reported, never called. The certificate is shared by
     * every handset in its production run, and Google documents expired factory
     * keys as still trustworthy.
     */
    @Test
    fun expiredIssuerIsAWarningNotAFinding() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=Android Keystore Software Attestation Intermediate", year2024 - 1, year2024),
        )
        val s = evaluate(chain, systemPatchYearMonth = 202601)
        assertEquals(ValidityOutcome.EXPIRED_ISSUER, s.outcome)
        assertFalse(s.isFinding)
        assertTrue(s.daysPastFloor!! > 300)

        val row = DetectionResult.fromBitmask(0, null, null, s)
            .single { it.flag == DetectionResult.DETECTION_ATTEST_VALIDITY }
        assertFalse(row.detected)
        assertTrue(row.warning)
        assertTrue(row.detail!!.contains("still trustworthy"))
        assertTrue(row.detail!!.contains("shared across a production run"))
    }

    /** A rotation lag looks identical, so a recent lapse is never called. */
    @Test
    fun recentlyExpiredIsInconclusive() {
        val floorMonth = 202601
        val justBefore = year2026 - 86_400_000L * 10
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2024, justBefore),
        )
        val s = evaluate(chain, systemPatchYearMonth = floorMonth)
        assertEquals(ValidityOutcome.RECENTLY_EXPIRED, s.outcome)
        assertFalse(s.isFinding)
    }

    @Test
    fun healthyChainVerifies() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2024, year2030),
        )
        val s = evaluate(chain, systemPatchYearMonth = 202601)
        assertEquals(ValidityOutcome.VERIFIED, s.outcome)
        assertFalse(s.isFinding)
    }

    /**
     * A clock behind the floor is the state in which a genuine device serves a
     * lapsed certificate, so it suppresses the expiry arms rather than
     * compounding them.
     */
    @Test
    fun clockBehindSuppressesExpiry() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2024 - 1, year2024),
        )
        val s = ChainValidity.evaluate(
            chain = chain,
            pinnedRoots = listOf(root()),
            anchored = true,
            hardwareBacked = true,
            attestedPatchYearMonths = emptyList(),
            systemPatchYearMonth = 202601,
            nowMillis = year2024, // clock two years behind the 2026 floor
        )
        assertEquals(ValidityOutcome.CLOCK_BEHIND, s.outcome)
        assertFalse(s.isFinding)
    }

    /** Both emulators land here: a software, unanchored chain says nothing. */
    @Test
    fun unanchoredChainIsNotApplicable() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2024 - 1, year2024),
        )
        val s = ChainValidity.evaluate(
            chain = chain,
            pinnedRoots = listOf(root()),
            anchored = false,
            hardwareBacked = false,
            attestedPatchYearMonths = emptyList(),
            systemPatchYearMonth = 202601,
            nowMillis = year2026,
        )
        assertEquals(ValidityOutcome.NOT_APPLICABLE, s.outcome)
    }

    /**
     * An inverted window is reported even on an unanchored chain, because it
     * needs no reference at all to recognise.
     */
    @Test
    fun invertedWindowIsReportedEvenWhenUnanchored() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2030, year2024),
        )
        val s = ChainValidity.evaluate(
            chain = chain,
            pinnedRoots = listOf(root()),
            anchored = false,
            hardwareBacked = false,
            attestedPatchYearMonths = emptyList(),
            systemPatchYearMonth = null,
            nowMillis = year2026,
        )
        assertEquals(ValidityOutcome.IMPOSSIBLE_WINDOW, s.outcome)
    }

    /**
     * chainAnchorsToPinnedRoot answers true vacuously on an empty pinned set,
     * which is the one configuration where this code knows least. It must route
     * to no-reference, not to a finding.
     */
    @Test
    fun emptyPinnedSetNeverOpensTheGate() {
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2024 - 1, year2024),
        )
        val s = ChainValidity.evaluate(
            chain = chain,
            pinnedRoots = emptyList(),
            anchored = true,
            hardwareBacked = true,
            attestedPatchYearMonths = emptyList(),
            systemPatchYearMonth = 202601,
            nowMillis = year2026,
        )
        assertEquals(ValidityOutcome.NOT_APPLICABLE, s.outcome)
    }

    /**
     * Google publishes several root certificates sharing one key, so an anchor
     * must be excluded by public key rather than by encoded bytes, or a
     * re-issued instance of a pinned root would have its own window judged.
     */
    @Test
    fun anchorsAreExcludedByPublicKeyNotBytes() {
        val anchor = root()
        val reissued = cert("CN=f92009e853b6b045", year2024 - 1, year2024, key = anchor.publicKey)
        val chain = listOf(cert("CN=leaf", 0L, year2030), reissued)
        assertTrue(ChainValidity.issuerCertificates(chain, listOf(anchor)).isEmpty())

        val s = evaluate(chain, pinnedRoots = listOf(anchor), systemPatchYearMonth = 202601)
        assertEquals(ValidityOutcome.NOT_APPLICABLE, s.outcome)
    }

    @Test
    fun selfSignedElementsAreExcluded() {
        val selfSigned = cert("CN=some root", year2024 - 1, year2024, selfSigned = true)
        val chain = listOf(cert("CN=leaf", 0L, year2030), selfSigned)
        assertTrue(ChainValidity.issuerCertificates(chain, listOf(root())).isEmpty())
    }

    /**
     * RFC 5280 encodes pre-2050 years as UTCTime and Java maps a two-digit year
     * at or above 50 to 19YY, so a certificate expiring in 2050 can read back as
     * 1950 and look inverted. That is a parsing artefact, not a forgery.
     */
    @Test
    fun implausibleYearsAreNotTreatedAsInverted() {
        val year1950 = -631_152_000_000L
        val chain = listOf(
            cert("CN=leaf", 0L, year2030),
            cert("CN=intermediate", year2024, year1950),
        )
        val s = evaluate(chain, systemPatchYearMonth = 202601)
        assertFalse(s.isFinding)
    }

    @Test
    fun aChainWithNoIssuersIsNotApplicable() {
        val s = evaluate(listOf(cert("CN=leaf", 0L, year2030)))
        assertEquals(ValidityOutcome.NOT_APPLICABLE, s.outcome)
        assertEquals(ValidityOutcome.NOT_APPLICABLE, evaluate(emptyList()).outcome)
    }

    @Test
    fun theFloorUsesTheLatestWitness() {
        assertEquals(
            1_767_225_600_000L,
            ChainValidity.yearMonthToEpochMillis(202601)
        )
        assertNull(ChainValidity.yearMonthToEpochMillis(null))
        assertNull(ChainValidity.yearMonthToEpochMillis(202613))
        assertNull(ChainValidity.yearMonthToEpochMillis(200712))

        val floor = ChainValidity.timeFloor(
            issuers = listOf(cert("CN=i", year2024, year2030)),
            pinnedRoots = listOf(root()),
            attestedPatchYearMonths = listOf(202601),
            systemPatchYearMonth = 202412,
        )
        assertEquals(1_767_225_600_000L, floor)
    }

    @Test
    fun noWitnessMeansNoReference() {
        assertNull(
            ChainValidity.timeFloor(emptyList(), emptyList(), emptyList(), null)
        )
    }

    // ---- helpers -----------------------------------------------------------

    private fun evaluate(
        chain: List<X509Certificate>,
        pinnedRoots: List<X509Certificate> = listOf(root()),
        systemPatchYearMonth: Int? = null,
    ) = ChainValidity.evaluate(
        chain = chain,
        pinnedRoots = pinnedRoots,
        anchored = true,
        hardwareBacked = true,
        attestedPatchYearMonths = emptyList(),
        systemPatchYearMonth = systemPatchYearMonth,
        nowMillis = year2026,
    )

    private fun root() = cert("CN=pinned root", year2024, year2030, key = StubKey("root-key"))

    private fun cert(
        subject: String,
        notBefore: Long,
        notAfter: Long,
        key: PublicKey = StubKey(subject),
        selfSigned: Boolean = false,
    ): X509Certificate = StubCert(subject, notBefore, notAfter, key, selfSigned)

    private class StubKey(private val id: String) : PublicKey {
        override fun getAlgorithm() = "EC"
        override fun getFormat() = "X.509"
        override fun getEncoded(): ByteArray = id.toByteArray()
    }

    /**
     * A minimal X509Certificate. The analyser only reads the window, the public
     * key and the two principals, so everything else refuses to be called and
     * would surface immediately if the analyser started depending on it.
     */
    private class StubCert(
        private val subject: String,
        private val notBeforeMillis: Long,
        private val notAfterMillis: Long,
        private val key: PublicKey,
        private val selfSigned: Boolean,
    ) : X509Certificate() {
        override fun getNotBefore(): Date = Date(notBeforeMillis)
        override fun getNotAfter(): Date = Date(notAfterMillis)
        override fun getPublicKey(): PublicKey = key
        override fun getSubjectX500Principal() = X500Principal(subject)
        override fun getIssuerX500Principal() =
            X500Principal(if (selfSigned) subject else "CN=issuer of $subject")

        override fun checkValidity() = error("the analyser must never read the clock this way")
        override fun checkValidity(date: Date?) = error("not used")
        override fun getVersion() = 3
        override fun getSerialNumber(): BigInteger = BigInteger.ONE
        override fun getIssuerDN() = getIssuerX500Principal()
        override fun getSubjectDN() = getSubjectX500Principal()
        override fun getTBSCertificate() = ByteArray(0)
        override fun getSignature() = ByteArray(0)
        override fun getSigAlgName() = "SHA256withECDSA"
        override fun getSigAlgOID() = "1.2.840.10045.4.3.2"
        override fun getSigAlgParams(): ByteArray? = null
        override fun getIssuerUniqueID(): BooleanArray? = null
        override fun getSubjectUniqueID(): BooleanArray? = null
        override fun getKeyUsage(): BooleanArray? = null
        override fun getBasicConstraints() = -1
        override fun getEncoded() = subject.toByteArray()
        override fun verify(key: PublicKey?) = Unit
        override fun verify(key: PublicKey?, sigProvider: String?) = Unit
        override fun toString() = subject
        override fun hasUnsupportedCriticalExtension() = false
        override fun getCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
        override fun getNonCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
        override fun getExtensionValue(oid: String?): ByteArray? = null
    }
}
