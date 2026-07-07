package com.example.sam_agent

import androidx.appfunctions.service.AppFunction
import androidx.appfunctions.AppFunctionContext
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

// JNA Interface for libsam.so
interface SamLib : Library {
    fun GetMeshInfo(): Pointer?
    fun CallRemoteTool(peerId: String, toolName: String, argsJson: String): Pointer?
    fun FreeString(ptr: Pointer)
}

class SamFunctions {

    // Load the library lazily
    private val samLib: SamLib by lazy {
        Native.load("sam", SamLib::class.java) as SamLib
    }

    /**
     * Retrieves the current status and statistics of the SAM mesh node.
     * Returns a JSON string containing connected_peers, dht_size, and node_id.
     */
    @AppFunction(isDescribedByKDoc = true)
    suspend fun getMeshStatus(context: AppFunctionContext): String {
        return try {
            val ptr = samLib.GetMeshInfo()
            if (ptr != null) {
                val json = ptr.getString(0)
                samLib.FreeString(ptr)
                json ?: "{\"error\": \"null response\"}"
            } else {
                "{\"error\": \"failed to call GetMeshInfo\"}"
            }
        } catch (e: Exception) {
            "{\"error\": \"${e.message}\"}"
        }
    }

    /**
     * Calls an MCP tool on a remote peer in the SAM mesh.
     * @param peerId The ID of the remote peer.
     * @param toolName The name of the tool to call (namespaced, e.g., 'scheme://service/tool').
     * @param argsJson The arguments for the tool call as a JSON string (e.g., '{"key": "value"}').
     */
    @AppFunction(isDescribedByKDoc = true)
    suspend fun callRemoteMeshTool(context: AppFunctionContext, peerId: String, toolName: String, argsJson: String): String {
        return try {
            val ptr = samLib.CallRemoteTool(peerId, toolName, argsJson)
            if (ptr != null) {
                val json = ptr.getString(0)
                samLib.FreeString(ptr)
                json ?: "{\"error\": \"null response\"}"
            } else {
                "{\"error\": \"failed to call CallRemoteTool\"}"
            }
        } catch (e: Exception) {
            "{\"error\": \"${e.message}\"}"
        }
    }
}
