package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.os.Build
import android.util.Log

/**
 * Reads the platform's own module-set blob, the value the attested moduleHash is
 * a digest over.
 *
 * Reached by reflection on purpose. KeyStoreManager and
 * getSupplementaryAttestationInfo are API 36, and a vendor build that omits the
 * flagged API raises NoClassDefFoundError or NoSuchMethodError during class
 * verification rather than at the call. Reflection keeps every such failure
 * inside one try block and keeps the rest of the app loadable on any platform.
 */
object PlatformModuleInfo {

    private const val TAG = "PlatformModuleInfo"
    private const val SDK_MODULE_HASH = 36
    private const val KEYSTORE_SERVICE = "keystore"

    /** Null whenever the platform cannot supply the blob, which is no evidence. */
    fun read(context: Context): ByteArray? {
        if (Build.VERSION.SDK_INT < SDK_MODULE_HASH) return null
        return try {
            val clazz = Class.forName("android.security.keystore.KeyStoreManager")
            val tag = clazz.getField("MODULE_HASH").getInt(null)
            val manager = context.getSystemService(KEYSTORE_SERVICE)
                ?: clazz.getMethod("getInstance").invoke(null)
                ?: return null
            val method = clazz.getMethod("getSupplementaryAttestationInfo", Int::class.javaPrimitiveType)
            method.invoke(manager, tag) as? ByteArray
        } catch (e: Throwable) {
            // Absent, unimplemented or refused. All of them mean the comparison
            // has nothing to compare against.
            Log.d(TAG, "module info unavailable: ${e.javaClass.simpleName}")
            null
        }
    }
}
