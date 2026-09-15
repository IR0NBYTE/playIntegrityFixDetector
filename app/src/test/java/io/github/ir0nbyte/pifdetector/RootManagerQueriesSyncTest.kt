package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64

class RootManagerQueriesSyncTest {
    @Test
    fun everyNativeRootManagerProbeIsDeclaredInManifestQueries() {
        val native = nativeProbedPackages()
        val manifest = manifestQueriedPackages()

        assertTrue("no packages parsed out of native-lib.cpp", native.isNotEmpty())
        assertTrue("no <package> entries parsed out of the manifest", manifest.isNotEmpty())

        val invisibleOnApi30Plus = native - manifest
        assertEquals(
            "native probes these packages but the manifest does not declare them, " +
                "so PackageManager hides them from API 30 and the probe silently " +
                "reports them as absent: $invisibleOnApi30Plus",
            emptySet<String>(),
            invisibleOnApi30Plus
        )

        val declaredButUnused = manifest - native
        assertEquals(
            "the manifest declares <queries> packages the native probe never " +
                "looks for, which widens the app's declared package visibility " +
                "for no benefit: $declaredButUnused",
            emptySet<String>(),
            declaredButUnused
        )
    }

    @Test
    fun everyNativeRootManagerLiteralDecodesToAPackageName() {
        val malformed = nativeProbedPackages().filterNot {
            it.matches(Regex("""[a-z][a-z0-9_]*(\.[a-z0-9_]+)+"""))
        }
        assertEquals("mis-encoded package literal(s) in native-lib.cpp", emptyList<String>(), malformed)
    }

    private fun nativeProbedPackages(): Set<String> {
        val src = repoFile("src/main/cpp/native-lib.cpp").readText()
        val block = Regex("""static const std::string pkgs\[] = \{(.*?)};""", RegexOption.DOT_MATCHES_ALL)
            .find(src)?.groupValues?.get(1)
            ?: error("could not locate the pkgs[] array in native-lib.cpp")
        return Regex("""base64_decode\("([^"]+)"\)""").findAll(block)
            .map { deobfuscate(it.groupValues[1]) }
            .toSet()
    }

    private fun manifestQueriedPackages(): Set<String> {
        val xml = repoFile("src/main/AndroidManifest.xml").readText()
        val queries = Regex("""<queries>(.*?)</queries>""", RegexOption.DOT_MATCHES_ALL)
            .find(xml)?.groupValues?.get(1) ?: return emptySet()
        return Regex("""<package\s+android:name="([^"]+)"""").findAll(queries)
            .map { it.groupValues[1] }
            .toSet()
    }

    private fun deobfuscate(encoded: String): String {
        val raw = Base64.getDecoder().decode(encoded)
        val key = "0XDALI".toByteArray()
        return String(ByteArray(raw.size) { (raw[it].toInt() xor key[it % key.size].toInt()).toByte() })
    }

    private fun repoFile(relative: String): File {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            for (candidate in listOf(File(dir, relative), File(dir, "app/$relative"))) {
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        error("could not locate $relative from ${File("").absolutePath}")
    }
}
