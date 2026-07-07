import 'package:flutter_test/flutter_test.dart';
import 'package:sam_agent/mcp_server.dart';

void main() {
  group('SamDartMcpServer Compliance Tests', () {
    late SamDartMcpServer server;
    bool batteryEnabled = true;
    bool locationEnabled = true;

    setUp(() {
      server = SamDartMcpServer(
        isBatteryEnabled: () => batteryEnabled,
        isLocationEnabled: () => locationEnabled,
      );
    });

    test('Handle initialize request', () async {
      final request = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'initialize',
        'params': {
          'protocolVersion': '2024-11-05',
          'capabilities': {},
          'clientInfo': {'name': 'test-client', 'version': '1.0.0'}
        }
      };

      final response = await server.handleMcpRequest(request);

      expect(response, isNotNull);
      expect(response!['jsonrpc'], '2.0');
      expect(response['id'], 1);
      expect(response['result'], isNotNull);
      expect(response['result']['protocolVersion'], '2024-11-05');
      expect(response['result']['serverInfo']['name'], 'sam-dart-sensors');
    });

    test('Handle notifications/initialized (should return null for no body)', () async {
      final request = {
        'jsonrpc': '2.0',
        // No ID for notifications
        'method': 'notifications/initialized',
        'params': {}
      };

      final response = await server.handleMcpRequest(request);

      // Null response indicates HTTP 202 Accepted with no body
      expect(response, isNull);
    });

    test('Handle tools/list request', () async {
      final request = {
        'jsonrpc': '2.0',
        'id': 2,
        'method': 'tools/list',
        'params': {}
      };

      final response = await server.handleMcpRequest(request);

      expect(response, isNotNull);
      expect(response!['id'], 2);
      expect(response['result'], isNotNull);
      final tools = response['result']['tools'] as List;
      expect(tools.length, 2);
      expect(tools[0]['name'], 'get_battery_status');
      expect(tools[1]['name'], 'get_location');
    });

    test('Handle tools/list request with disabled battery', () async {
      batteryEnabled = false;
      final request = {
        'jsonrpc': '2.0',
        'id': 3,
        'method': 'tools/list',
        'params': {}
      };

      final response = await server.handleMcpRequest(request);

      expect(response, isNotNull);
      final tools = response!['result']['tools'] as List;
      expect(tools.length, 1);
      expect(tools[0]['name'], 'get_location');
      
      // Reset
      batteryEnabled = true;
    });

    test('Handle unhandled method', () async {
      final request = {
        'jsonrpc': '2.0',
        'id': 4,
        'method': 'unsupported/method',
        'params': {}
      };

      final response = await server.handleMcpRequest(request);

      expect(response, isNotNull);
      expect(response!['error'], isNotNull);
      expect(response['error']['code'], -32601); // Method not implemented
    });
  });
}
