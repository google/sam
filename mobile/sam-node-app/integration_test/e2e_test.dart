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
    final oidcIssuer = 'http://10.0.2.2:18080';
    final tokenURL = '$oidcIssuer/token';

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
    final hubURL = 'http://10.0.2.2:37001';
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
      'enableRelay': false,
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
    mockMcpServer.listen((HttpRequest request) {
      request.response
        ..headers.contentType = ContentType.json
        ..statusCode = HttpStatus.ok
        ..write(jsonEncode({
          'jsonrpc': '2.0',
          'id': 1,
          'result': {
            'content': [
              {
                'type': 'text',
                'text': 'Hello from Android!'
              }
            ]
          }
        }));
      request.response.close();
    });

    // Register a dummy MCP service inside the Android emulator
    final registerUrl = 'http://127.0.0.1:8080/sam/service/register';
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

    // Discover host-tool from inside the emulator via its local MCP API
    final listToolsUrl = 'http://127.0.0.1:8080/mcp';
    var discovered = false;
    for (var i = 0; i < 30; i++) {
      try {
        final listResponse = await http.post(
          Uri.parse(listToolsUrl),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-token',
          },
          body: jsonEncode({
            'jsonrpc': '2.0',
            'method': 'tools/list',
            'params': {},
            'id': 1
          }),
        );
        if (listResponse.statusCode == 200) {
          final listData = jsonDecode(listResponse.body);
          final result = listData['result'];
          if (result != null && result['tools'] != null) {
            final tools = result['tools'] as List;
            if (tools.any((t) => t['name'] == 'host-tool')) {
              discovered = true;
              break;
            }
          }
        }
      } catch (e) {
        // ignore network setup transient errors
      }
      await Future.delayed(const Duration(seconds: 1));
    }
    expect(discovered, isTrue, reason: 'Emulator failed to discover host-tool');

    // Call host-tool from inside the emulator via its local MCP API
    final callToolUrl = 'http://127.0.0.1:8080/mcp';
    var called = false;
    for (var i = 0; i < 10; i++) {
      try {
        final callResponse = await http.post(
          Uri.parse(callToolUrl),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-token',
          },
          body: jsonEncode({
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {
              'name': 'host-tool',
              'arguments': {}
            },
            'id': 1
          }),
        );
        if (callResponse.statusCode == 200) {
          final callData = jsonDecode(callResponse.body);
          final result = callData['result'];
          if (result != null && result['content'] != null) {
            final content = result['content'] as List;
            if (content.any((c) => c['text'].contains('Hello from Host!'))) {
              called = true;
              break;
            }
          }
        }
      } catch (e) {
        // ignore network setup transient errors
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
}
