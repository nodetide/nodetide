package eu.kuklin.nodetide.protocol

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object BcEd25519 : Ed25519Verifier {
    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }
}

/** A signer from a 32-byte seed. Ed25519 is deterministic, so the same seed and message give the same signature as the Python reference. */
class SeedSigner(seedHex: String) : Signer {
    private val key = Ed25519PrivateKeyParameters(Hex.decode(seedHex)!!, 0)
    override val publicKeyHex: String = Hex.encode(key.generatePublicKey().encoded)

    override fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, key)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}
