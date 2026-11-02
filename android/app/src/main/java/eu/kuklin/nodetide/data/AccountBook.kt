package eu.kuklin.nodetide.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/** One identity held on this phone with its cached chain (raw events: control chain, then content track). */
@Serializable
data class Account(val identity: LocalIdentity, val chain: List<JsonObject> = emptyList()) {
    val hash: String get() = identity.identityHash

    /** Watch-only: an identity followed by its public data, with no key of any kind here (a paired device holds its device key). */
    val watchOnly: Boolean get() = identity.signingSecretKey.isEmpty() && identity.deviceSigningSecretKey.isNullOrEmpty()

    /** A device of an identity whose master key is elsewhere: it signs with its own device key only. */
    val deviceOnly: Boolean get() = identity.signingSecretKey.isEmpty() && !identity.deviceSigningSecretKey.isNullOrEmpty()
}

/**
 * Every account on this phone and which one is active. Pure data with no Android dependency, so the rules (one account per
 * identity, removing the active one picks another, an unknown account cannot be activated) are unit-tested on the JVM.
 *
 * The screens read "the current identity"; that is the active account.
 */
@Serializable
data class AccountBook(val accounts: List<Account> = emptyList(), val active: String? = null) {
    /** The active account; if the recorded one is gone, the first. Null only when there are no accounts. */
    val current: Account? get() = accounts.firstOrNull { it.hash == active } ?: accounts.firstOrNull()

    operator fun contains(hash: String) = accounts.any { it.hash == hash }

    /** Add the account, or replace the one for the same identity (keeping its chain if the new one has none). */
    fun with(account: Account, makeActive: Boolean = true): AccountBook {
        val existing = accounts.firstOrNull { it.hash == account.hash }
        val merged = if (existing != null && account.chain.isEmpty()) account.copy(chain = existing.chain) else account
        val list = if (existing == null) accounts + merged else accounts.map { if (it.hash == account.hash) merged else it }
        return AccountBook(list, if (makeActive || active == null) account.hash else active)
    }

    /** Make an existing account the active one (unknown hashes are ignored). */
    fun activate(hash: String): AccountBook = if (hash in this) copy(active = hash) else this

    /** Remove an account. If it was the active one, the next remaining account becomes active. */
    fun without(hash: String): AccountBook {
        val index = accounts.indexOfFirst { it.hash == hash }
        if (index < 0) return this
        val rest = accounts.filterNot { it.hash == hash }
        val nextActive = when {
            rest.isEmpty() -> null
            active != hash -> active
            else -> rest[minOf(index, rest.size - 1)].hash
        }
        return AccountBook(rest, nextActive)
    }

    fun withChain(hash: String, chain: List<JsonObject>): AccountBook =
        copy(accounts = accounts.map { if (it.hash == hash) it.copy(chain = chain) else it })

    fun encode(): String = format.encodeToString(this)

    companion object {
        private val format = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        fun decode(text: String?): AccountBook =
            if (text.isNullOrBlank()) AccountBook() else runCatching { format.decodeFromString<AccountBook>(text) }.getOrDefault(AccountBook())
    }
}
