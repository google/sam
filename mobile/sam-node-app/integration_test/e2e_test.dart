// ignore_for_file: avoid_print
import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sam_agent/sam_ffi.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('E2E Mesh Communication Test', (WidgetTester tester) async {
    final samLib = SamNodeLib();

    // 1. Get local app directories
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_e2e_data';

    // Cleanup old data
    final dir = Directory(dataDir);
    if (dir.existsSync()) {
      dir.deleteSync(recursive: true);
    }

    // 2. Fetch OIDC JWT from the mock OIDC server running on host
    // Host IP from emulator is 10.0.2.2
    const oidcIssuer = 'http://10.0.2.2:18080';
    const tokenURL = '$oidcIssuer/token';

    final response = await http.post(
      Uri.parse(tokenURL),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: {
        'grant_type': 'client_credentials',
        'client_id': 'test-client',
        'client_secret': 'test-secret',
      },
    );
    expect(response.statusCode, equals(200));
    final tokenData = jsonDecode(response.body);
    final jwt = tokenData['access_token'] as String;
    expect(jwt, isNotEmpty);

    // 3. Enroll Node against host Hub
    const hubURL = 'http://10.0.2.2:37001';
    final enrollErr = samLib.enroll(dataDir, hubURL, jwt, true);
    expect(enrollErr, isNull);

    // 4. Start Node
    final startErr = samLib.start({
      'dataDir': dataDir,
      'hubURL': hubURL,
      'meshID': 'public-mesh',
      'bindAddr': '0.0.0.0:8080', // sidecar HTTP server inside phone
      'apiToken': 'test-token',
      'allowLoopback': true,
      'enableRelay': true,
      'logLevel': 'debug',
    });
    expect(startErr, isNull);

    // Wait for node to initialize host connection
    await Future.delayed(const Duration(seconds: 5));

    final nodeID = samLib.getNodeID();
    expect(nodeID, isNotNull);
    expect(nodeID, isNotEmpty);
    expect(nodeID, isNot('unauthenticated'));

    // Start local Mock MCP Server inside the Android emulator
    final mockMcpServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 9090);
    mockMcpServer.listen((HttpRequest request) async {
      try {
        final content = await utf8.decoder.bind(request).join();
        final body = jsonDecode(content);
        final method = body['method'] as String?;
        final id = body['id'];

        dynamic result;
        if (method == 'initialize') {
          result = {
            'protocolVersion': '2024-11-05',
            'capabilities': {},
            'serverInfo': {'name': 'mock-emulator-mcp', 'version': '1.0.0'}
          };
        } else if (method == 'tools/list') {
          result = {
            'tools': [
              {
                'name': 'emulator-tool',
                'description': 'test tool on emulator',
                'inputSchema': {'type': 'object', 'properties': {}}
              }
            ]
          };
        } else if (method == 'tools/call') {
          result = {
            'content': [
              {'type': 'text', 'text': 'Hello from Android!'}
            ]
          };
        }

        request.response
          ..headers.contentType = ContentType.json
          ..statusCode = HttpStatus.ok
          ..write(jsonEncode({
            'jsonrpc': '2.0',
            'id': id,
            'result': result,
          }));
      } catch (e) {
        request.response
          ..statusCode = HttpStatus.internalServerError
          ..write(e.toString());
      } finally {
        await request.response.close();
      }
    });

    // Register a dummy MCP service inside the Android emulator
    const registerUrl = 'http://127.0.0.1:8080/sam/service/register';
    final regResponse = await http.post(
      Uri.parse(registerUrl),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token',
      },
      body: jsonEncode({
        'service': {
          'type': 'SERVICE_TYPE_MCP',
          'name': 'emulator-tool',
          'description': 'test tool inside emulator'
        },
        'targetUrl': 'http://127.0.0.1:9090' // point to local Dart mock server
      }),
    );
    expect(regResponse.statusCode, equals(200));

    // Discover host-tool from inside the emulator via its local MCP API using McpClient
    final client = McpClient('http://127.0.0.1:8080/mcp', 'test-token');
    var initialized = false;
    for (var i = 0; i < 10; i++) {
      try {
        await client.initialize();
        initialized = true;
        break;
      } catch (e) {
        print('E2E McpClient initialization attempt failed: $e');
      }
      await Future.delayed(const Duration(seconds: 1));
    }
    expect(initialized, isTrue, reason: 'Emulator failed to initialize McpClient session');

    var discovered = false;
    String hostToolName = 'host-tool';
    String hostPeerId = '';
    for (var i = 0; i < 30; i++) {
      try {
        final callResult = await client.post('tools/call', {
          'name': 'find_remote_tools',
          'arguments': {}
        });
        print('E2E Discovered Tools Result: $callResult');
        if (callResult != null && callResult['content'] != null) {
          final contentList = callResult['content'] as List;
          if (contentList.isNotEmpty) {
            final text = contentList[0]['text'] as String;
            final tools = jsonDecode(text) as List;
            final matched = tools.firstWhere(
              (t) => (t['tool_name'] as String).contains('host-tool'),
              orElse: () => null,
            );
            if (matched != null) {
              hostToolName = matched['tool_name'] as String;
              hostPeerId = matched['peer_id'] as String;
              discovered = true;
              break;
            }
          }
        }
      } catch (e) {
        print('E2E Discovery attempt failed: $e');
      }
      await Future.delayed(const Duration(seconds: 1));
    }
    expect(discovered, isTrue, reason: 'Emulator failed to discover host-tool');

    // Call host-tool from inside the emulator via its local MCP API using McpClient
    var called = false;
    for (var i = 0; i < 10; i++) {
      try {
        final callResult = await client.post('tools/call', {
          'name': 'call_remote_tool',
          'arguments': {
            'peer_id': hostPeerId,
            'tool_name': hostToolName,
          }
        });
        print('E2E Call Result: $callResult');
        if (callResult != null && callResult['content'] != null) {
          final content = callResult['content'] as List;
          if (content.any((c) => c['text'].contains('Hello from Host!'))) {
            called = true;
            break;
          }
        }
      } catch (e) {
        print('E2E Call attempt failed: $e');
      }
      await Future.delayed(const Duration(seconds: 1));
    }
    expect(called, isTrue, reason: 'Emulator failed to execute host-tool');

    // Wait some time to let the host verify connection and discover emulator-tool
    await Future.delayed(const Duration(seconds: 10));

    // Cleanup & Stop
    await mockMcpServer.close();
    final stopErr = samLib.stop();
    expect(stopErr, isNull);
  });

  tearDownAll(() async {
    try {
      final appDir = await getApplicationDocumentsDirectory();
      final file = File('${appDir.path}/sam_e2e_data/node.log');
      if (file.existsSync()) {
        print('=== MOBILE GO NODE LOGS ===');
        print(file.readAsStringSync());
        print('===========================');
      } else {
        print('No node.log file found at ${file.path}');
      }
    } catch (e) {
      print('Failed to print node.log: $e');
    }
  });
}

class McpClient {
  final String url;
  final String token;
  String? sessionId;

  McpClient(this.url, this.token);

  Future<dynamic> post(String method, Map<String, dynamic> params) async {
    final Map<String, String> headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'Authorization': 'Bearer $token',
    };
    if (sessionId != null) {
      headers['Mcp-Session-Id'] = sessionId!;
    }

    final Map<String, dynamic> bodyMap = {
      'jsonrpc': '2.0',
      'method': method,
      'params': params,
    };
    if (!method.startsWith('notifications/')) {
      bodyMap['id'] = 1;
    }

    final response = await http.post(
      Uri.parse(url),
      headers: headers,
      body: jsonEncode(bodyMap),
    );

    // Save session ID if returned in headers
    final returnedSessionId = response.headers['mcp-session-id'] ?? response.headers['Mcp-Session-Id'];
    if (returnedSessionId != null) {
      sessionId = returnedSessionId;
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('HTTP error ${response.statusCode}: ${response.body}');
    }

    // Parse the SSE body
    final body = response.body;
    String jsonData = '';
    for (var line in body.split('\n')) {
      if (line.startsWith('data: ')) {
        jsonData = line.substring(6);
        break;
      }
    }

    if (jsonData.isEmpty) {
      if (method.startsWith('notifications/')) {
        return null;
      }
      throw Exception('No data block found in SSE response: $body');
    }

    final dataObj = jsonDecode(jsonData);
    if (dataObj['error'] != null) {
      throw Exception('JSON-RPC error: ${dataObj['error']}');
    }
    return dataObj['result'];
  }

  Future<void> initialize() async {
    await post('initialize', {
      'protocolVersion': '2024-11-05',
      'capabilities': {},
      'clientInfo': {
        'name': 'e2e-dart-client',
        'version': '1.0.0'
      }
    });

    await post('notifications/initialized', {});
  }
}
