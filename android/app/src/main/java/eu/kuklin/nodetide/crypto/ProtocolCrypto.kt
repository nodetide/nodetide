package eu.kuklin.nodetide.crypto

import eu.kuklin.nodetide.protocol.Ed25519Verifier
import eu.kuklin.nodetide.protocol.Signer

/** Ed25519 verification for the protocol module, backed by libsodium. */
object SodiumVerifier : Ed25519Verifier {
    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        SigningKeyPair.verify(publicKey, message, signature)
}

/** A [Signer] over one of the app's Ed25519 keys. */
class KeySigner(private val keys: SigningKeyPair) : Signer {
    override val publicKeyHex: String get() = keys.publicKeyHex
    override fun sign(message: ByteArray): ByteArray = keys.sign(message)
}
