package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Null and empty mean very different things for this parser. An empty set would
 * answer "not listed" for every serial, so anything that is not a usable
 * revocation list must be discarded outright.
 */
class AttestationStatusClientTest {

    @Test
    fun parsesOnlyRevokedAndSuspended() {
        val json = """
            {"entries":{
              "aaaa1111":{"status":"REVOKED","reason":"KEY_COMPROMISE"},
              "bbbb2222":{"status":"SUSPENDED"},
              "cccc3333":{"status":"UNKNOWN"}
            }}
        """.trimIndent()
        val parsed = AttestationStatusClient.parseRevokedSerials(json)
        assertNotNull(parsed)
        assertEquals(setOf("aaaa1111", "bbbb2222"), parsed)
    }

    /** The captive-portal and blinded-check guard. */
    @Test
    fun emptyEntriesReturnsNull() {
        assertNull(AttestationStatusClient.parseRevokedSerials("""{"entries":{}}"""))
    }

    @Test
    fun missingEntriesReturnsNull() {
        assertNull(AttestationStatusClient.parseRevokedSerials("""{"other":1}"""))
    }

    @Test
    fun malformedJsonReturnsNull() {
        assertNull(AttestationStatusClient.parseRevokedSerials("<html>login</html>"))
    }

    @Test
    fun uppercaseKeysAreLowercased() {
        val json = """{"entries":{"ABCDEF0123456789":{"status":"REVOKED"}}}"""
        val parsed = AttestationStatusClient.parseRevokedSerials(json)
        assertNotNull(parsed)
        assertTrue(parsed!!.contains("abcdef0123456789"))
    }

    @Test
    fun entriesWithNoUsableStatusYieldEmptySetNotNull() {
        // A well-formed list whose every entry is filtered out is still a
        // structurally valid response; the size floor in fetchRevokedSerials is
        // what rejects it as a source.
        val json = """{"entries":{"aaaa1111":{"status":"UNKNOWN"}}}"""
        val parsed = AttestationStatusClient.parseRevokedSerials(json)
        assertNotNull(parsed)
        assertTrue(parsed!!.isEmpty())
    }
}
