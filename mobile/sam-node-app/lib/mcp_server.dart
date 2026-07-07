import 'dart:io';
import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

class SamDartMcpServer {
  static const MethodChannel _channel = MethodChannel('com.example.sam_agent/mesh_expose');
  HttpServer? _server;
  final List<HttpResponse> _sseClients = [];

  // Callbacks to check current feature status from UI
  final bool Function() isBatteryEnabled;
  final bool Function() isLocationEnabled;

  SamDartMcpServer({
    required this.isBatteryEnabled,
    required this.isLocationEnabled,
  });

  /// Starts the Dart HTTP Server acting as an MCP backend
  Future<void> start({int port = 9090, required String goSidecarPort, required String apiToken}) async {
    try {
      _server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
      debugPrint('SAM Dart MCP Server listening on port $port');

      _server!.listen((HttpRequest request) async {
        // Handle CORS if needed, but since it's loopback and called by Go, maybe not strict
        if (request.method == 'GET') {
          _handleSse(request);
        } else if (request.method == 'POST') {
          _handlePost(request);
        } else {
          request.response.statusCode = HttpStatus.methodNotAllowed;
          await request.response.close();
        }
      });

      // Register this service with the local SAM Go Node
      await registerService(
        goSidecarPort: goSidecarPort,
        apiToken: apiToken,
        serviceName: 'phone-sensors',
        targetUrl: 'http://127.0.0.1:$port',
        description: 'Exposes phone sensors like battery and location to the SAM mesh',
      );

    } catch (e) {
      debugPrint('Failed to start Dart MCP Server: $e');
    }
  }

  /// Stops the server
  Future<void> stop() async {
    await _server?.close(force: true);
    _sseClients.clear();
    debugPrint('SAM Dart MCP Server stopped');
  }

  /// Handles SSE (Server-Sent Events) for MCP stream
  void _handleSse(HttpRequest request) async {
    request.response.headers.contentType = ContentType('text', 'event-stream');
    request.response.headers.add('Cache-Control', 'no-cache');
    request.response.headers.add('Connection', 'keep-alive');
    
    _sseClients.add(request.response);
    
    // Initial connection event
    request.response.write('event: connected\ndata: {}\n\n');
    await request.response.flush();
  }

  /// Handles MCP JSON-RPC Requests
  void _handlePost(HttpRequest request) async {
    final body = await utf8.decoder.bind(request).join();
    
    try {
      final jsonRpc = jsonDecode(body);
      final id = jsonRpc['id'];

      final response = await handleMcpRequest(jsonRpc);
      
      if (response == null) {
        // It was a notification or unhandled non-request
        if (id == null) {
          request.response.statusCode = HttpStatus.accepted; // 202 Accepted
        } else {
          request.response.statusCode = HttpStatus.notFound;
        }
        await request.response.close();
        return;
      }

      _sendJsonResponse(request, response);

    } catch (e) {
      debugPrint('Error processing MCP request: $e');
      _sendJsonError(request, null, -32700, 'Parse error');
    }
  }

  /// Core MCP Logic separated for testability
  Future<Map<String, dynamic>?> handleMcpRequest(Map<String, dynamic> jsonRpc) async {
    final method = jsonRpc['method'];
    final id = jsonRpc['id'];

    // 1. Handshake
    if (method == 'initialize') {
        return {
          'jsonrpc': '2.0',
          'id': id,
          'result': {
            'protocolVersion': '2024-11-05',
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'sam-dart-sensors', 'version': '1.0.0'}
          }
        };
    }
    
    // 2. List Tools
    if (method == 'tools/list') {
        final tools = [];
        
        if (isBatteryEnabled()) {
          tools.add({
            'name': 'get_battery_status',
            'description': 'Returns the current battery level and charging status of the device.',
            'inputSchema': {'type': 'object', 'properties': {}}
          });
        }
        
        if (isLocationEnabled()) {
          tools.add({
            'name': 'get_location',
            'description': 'Returns the current coarse location of the device.',
            'inputSchema': {'type': 'object', 'properties': {}}
          });
        }

        return {
          'jsonrpc': '2.0',
          'id': id,
          'result': {
            'tools': tools
          }
        };
    }

    // 3. Call Tool
    if (method == 'tools/call') {
        final params = jsonRpc['params'];
        final toolName = params['name'];
        
        if (toolName == 'get_battery_status' && isBatteryEnabled()) {
            try {
              final batteryData = await _channel.invokeMethod('getBatteryData');
              return {
                'jsonrpc': '2.0',
                'id': id,
                'result': {
                  'content': [{'type': 'text', 'text': batteryData.toString()}]
                }
              };
            } catch (e) {
              return {
                'jsonrpc': '2.0',
                'id': id,
                'error': {'code': -32000, 'message': 'Failed to get battery data: $e'}
              };
            }
        }
        
        if (toolName == 'get_location' && isLocationEnabled()) {
             try {
              final locationData = await _channel.invokeMethod('getLocationData');
              return {
                'jsonrpc': '2.0',
                'id': id,
                'result': {
                  'content': [{'type': 'text', 'text': locationData.toString()}]
                }
              };
            } catch (e) {
               return {
                'jsonrpc': '2.0',
                'id': id,
                'error': {'code': -32000, 'message': 'Failed to get location data: $e'}
              };
            }
        }
        
        return {
          'jsonrpc': '2.0',
          'id': id,
          'error': {'code': -32601, 'message': 'Method not found or disabled'}
        };
    }

    // If it's a notification (no ID), we return null to indicate no body response
    if (id == null) {
      return null;
    }

    return {
      'jsonrpc': '2.0',
      'id': id,
      'error': {'code': -32601, 'message': 'Method not implemented'}
    };
  }

  void _sendJsonResponse(HttpRequest request, Map<String, dynamic> response) async {
    request.response.headers.contentType = ContentType.json;
    request.response.write(jsonEncode(response));
    await request.response.close();
  }

  void _sendJsonError(HttpRequest request, dynamic id, int code, String message) async {
    final response = {
      'jsonrpc': '2.0',
      'id': id,
      'error': {
        'code': code,
        'message': message
      }
    };
    request.response.headers.contentType = ContentType.json;
    request.response.write(jsonEncode(response));
    await request.response.close();
  }

  /// Static helper to register any service (Embedded or External)
  static Future<bool> registerService({
    required String goSidecarPort,
    required String apiToken,
    required String serviceName,
    required String targetUrl,
    required String description,
  }) async {
    final url = 'http://127.0.0.1:$goSidecarPort/sam/service/register';
    
    try {
      final response = await http.post(
        Uri.parse(url),
        headers: {
          'Authorization': 'Bearer $apiToken',
          'Content-Type': 'application/json',
        },
        body: jsonEncode({
          'service': {
            'type': 1, // SERVICE_TYPE_MCP
            'name': serviceName,
            'description': description
          },
          'target_url': targetUrl
        }),
      );

      if (response.statusCode == 200) {
        debugPrint('Service "$serviceName" registered successfully with SAM Go Node!');
        return true;
      } else {
        debugPrint('Failed to register service "$serviceName": ${response.statusCode} - ${response.body}');
        return false;
      }
    } catch (e) {
      debugPrint('Error registering service "$serviceName": $e');
      return false;
    }
  }
}
