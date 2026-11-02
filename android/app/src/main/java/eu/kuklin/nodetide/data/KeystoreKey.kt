package eu.kuklin.nodetide.data

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * The AES-256 key that seals the accounts, kept in the Android Keystore: it cannot be exported, only used. It is made once,
 * preferring the strongest protection the phone offers (a dedicated secure chip, "StrongBox"; usable only while the phone is
 * unlocked) and falling back step by step on phones that cannot, so the app works everywhere but protects as much as it can.
 */
object KeystoreKey {
    private const val ALIAS = "nodetide.accounts.v1"
    private const val PROVIDER = "AndroidKeyStore"

    @Volatile private var cached: SecretKey? = null

    /** The key handle is looked up once per process: asking the Keystore for it every time costs tens of milliseconds. */
    @Synchronized
    fun get(): SecretKey {
        cached?.let { return it }
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { cached = it; return it }

        var last: Exception? = null
        // (strongBox, unlockedOnly): strongest first
        for ((strongBox, unlockedOnly) in listOf(true to true, false to true, false to false)) {
            try {
                return create(strongBox, unlockedOnly).also { cached = it }
            } catch (e: StrongBoxUnavailableException) {
                last = e
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException("could not create the Keystore key", last)
    }

    private fun create(strongBox: Boolean, unlockedOnly: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                if (unlockedOnly && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(true)
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).apply { init(spec) }.generateKey()
    }
}
