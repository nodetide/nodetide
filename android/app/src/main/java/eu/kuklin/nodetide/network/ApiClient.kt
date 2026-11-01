package eu.kuklin.nodetide.network

import eu.kuklin.nodetide.crypto.SodiumVerifier
import eu.kuklin.nodetide.data.*
import eu.kuklin.nodetide.protocol.ChainError
import eu.kuklin.nodetide.protocol.Options
import eu.kuklin.nodetide.protocol.Sigchain
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class ApiClient(private val baseUrl: String) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val jsonMediaType = "application/json".toMediaType()

    private fun errorOf(response: okhttp3.Response): Exception {
        val body = response.body?.string()
        return Exception("HTTP ${response.code}: ${body?.take(300) ?: response.message}")
    }

    /**
     * Get identity info from server.
     */
    suspend fun getIdentity(identityHash: String): Result<IdentityResponse> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder().url("$baseUrl/api/identities/$identityHash").get().build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext Result.failure(errorOf(response))
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<IdentityResponse>(body))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private suspend fun post(path: String, event: JsonObject): Result<SubmitEventResponse> = withContext(Dispatchers.IO) {
        try {
            val requestBody = JsonObject(mapOf("event" to event)).toString().toRequestBody(jsonMediaType)
            val request = Request.Builder().url("$baseUrl$path").post(requestBody).build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext Result.failure(errorOf(response))
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<SubmitEventResponse>(body))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Create the identity on the node (submit its genesis event).
     */
    suspend fun createIdentity(genesisEvent: JsonObject): Result<SubmitEventResponse> = post("/api/identities", genesisEvent)

    /**
     * Submit an event to the identity's chain. Control events and content events go to the same endpoint; the node routes
     * them by type. A 409 with "behind" means the node lacks a control event the event relies on.
     */
    suspend fun submitEvent(identityHash: String, event: JsonObject): Result<SubmitEventResponse> =
        post("/api/identities/$identityHash/events", event)

    /**
     * Download an identity's sigchain (both tracks; [light] = control chain only) and check it. The result carries the
     * events either way: [ChainDownload.verified] says whether they passed, [ChainDownload.problem] why not. Nothing a node
     * says about a chain is believed without this check.
     */
    suspend fun getSigchain(identityHash: String, light: Boolean = false): Result<ChainDownload> = withContext(Dispatchers.IO) {
        try {
            val url = "$baseUrl/api/identities/$identityHash/sigchain" + if (light) "?light=1" else ""
            val request = Request.Builder().url(url).get().build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext Result.failure(errorOf(response))
                val body = response.body?.string() ?: throw Exception("Empty response")
                val events = Json.parseToJsonElement(body).jsonObject.getValue("events").jsonArray.map { it.jsonObject }
                var verified = false
                var problem: String? = null
                try {
                    val chain = Sigchain.parse(events, Options(SodiumVerifier))
                    verified = chain.identityHash == identityHash
                    if (!verified) problem = "the chain is not the identity that was asked for"
                } catch (e: ChainError) {
                    problem = e.message
                }
                Result.success(ChainDownload(events, verified, problem))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Get public messages.
     */
    suspend fun getMessages(sender: String? = null, limit: Int = 50): Result<List<Message>> = withContext(Dispatchers.IO) {
        try {
            val url = buildString {
                append("$baseUrl/api/messages?limit=$limit")
                if (sender != null) append("&sender=$sender")
            }

            val request = Request.Builder()
                .url(url)
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                val messagesResponse = json.decodeFromString<MessagesResponse>(body)
                Result.success(messagesResponse.messages)
            } else {
                Result.failure(Exception("HTTP ${response.code}: ${response.message}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Publish a message.
     */
    suspend fun publishMessage(message: Message): Result<PublishMessageResponse> = withContext(Dispatchers.IO) {
        try {
            val requestBody = json.encodeToString(message).toRequestBody(jsonMediaType)

            val request = Request.Builder()
                .url("$baseUrl/api/messages")
                .post(requestBody)
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<PublishMessageResponse>(body))
            } else {
                val errorBody = response.body?.string()
                Result.failure(Exception("HTTP ${response.code}: $errorBody"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Get relay status.
     */
    suspend fun getRelayStatus(): Result<RelayStatus> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/relay/status")
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val body = response.body?.string() ?: throw Exception("Empty response")
                Result.success(json.decodeFromString<RelayStatus>(body))
            } else {
                Result.failure(Exception("HTTP ${response.code}: ${response.message}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Health check.
     */
    suspend fun healthCheck(): Result<Boolean> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/health")
                .get()
                .build()

            val response = client.newCall(request).execute()
            Result.success(response.isSuccessful)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

// Response types
/** A downloaded chain and the outcome of checking it. */
data class ChainDownload(val events: List<JsonObject>, val verified: Boolean, val problem: String?)

@kotlinx.serialization.Serializable
data class IdentityResponse(
    @kotlinx.serialization.SerialName("identity_hash") val identityHash: String,
    val name: String? = null,
    val type: String = "personal",
    @kotlinx.serialization.SerialName("master_pubkey") val masterPubkey: String = "",
    val verified: Boolean = false,
    @kotlinx.serialization.SerialName("sigchain_length") val sigchainLength: Int = 0,
)

/** The node's answer to a submitted event. */
@kotlinx.serialization.Serializable
data class SubmitEventResponse(
    val accepted: Boolean = true,
    @kotlinx.serialization.SerialName("identity_hash") val identityHash: String? = null,
    @kotlinx.serialization.SerialName("event_hash") val eventHash: String? = null,
    @kotlinx.serialization.SerialName("sigchain_length") val sigchainLength: Int = 0,
    @kotlinx.serialization.SerialName("content_length") val contentLength: Int = 0,
)

@kotlinx.serialization.Serializable
data class MessagesResponse(
    val messages: List<Message>,
    val total: Int = 0
)

@kotlinx.serialization.Serializable
data class PublishMessageResponse(
    @kotlinx.serialization.SerialName("message_hash") val messageHash: String
)
