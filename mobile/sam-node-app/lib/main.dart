import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_ai/firebase_ai.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:url_launcher/url_launcher.dart';

import 'sam_ffi.dart';
import 'mcp_server.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SAM Node Control',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const NodeControlPage(),
    );
  }
}

class NodeControlPage extends StatefulWidget {
  const NodeControlPage({super.key});

  @override
  State<NodeControlPage> createState() => _NodeControlPageState();
}

class _NodeControlPageState extends State<NodeControlPage> {
  final _hubController =
      TextEditingController(text: 'https://bananas.sam-mesh.dev');
  final _jwtController = TextEditingController();
  final _tokenController = TextEditingController(text: 'secret-token');
  
  static const _exposeChannel = MethodChannel('com.example.sam_agent/mesh_expose');

  late SamNodeLib _samLib;
  bool?
      _isEnrolled; // null = checking, false = show enrollment, true = show dashboard
  bool _running = false;
  String _status = 'Disconnected';
  String _nodeID = '';
  int _connectedPeers = 0;
  int _dhtSize = 0;
  bool _loggingIn = false;
  bool _devicePollingActive = false;
  Timer? _pollingTimer;

  // Local Services Exposure State
  bool _exposeBattery = false;
  bool _exposeLocation = false;

  // External MCP Bridging State
  final _externalMcpUrlController = TextEditingController(text: 'http://127.0.0.1:8080');
  final _externalMcpNameController = TextEditingController(text: 'android-remote');
  final _externalMcpDescController = TextEditingController(text: 'External Android Remote Control MCP');
  bool _externalMcpRegistered = false;

  late SamDartMcpServer _embeddedMcpServer;
  int _selectedTab = 0; // 0 = Dashboard, 1 = Services

  @override
  void initState() {
    super.initState();
    _samLib = SamNodeLib();
    _checkEnrollment();
    _embeddedMcpServer = SamDartMcpServer(
      isBatteryEnabled: () => _exposeBattery,
      isLocationEnabled: () => _exposeLocation,
    );
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _hubController.dispose();
    _jwtController.dispose();
    _tokenController.dispose();
    _externalMcpUrlController.dispose();
    _externalMcpNameController.dispose();
    _externalMcpDescController.dispose();
    super.dispose();
  }

  Future<void> _checkEnrollment() async {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final enrolled = _samLib.isEnrolled(dataDir);
    setState(() {
      _isEnrolled = enrolled;
      if (enrolled) {
        _status = 'Enrolled';
        // Try to get node ID if running (though might not be started yet)
        _nodeID = _samLib.getNodeID() ?? '';
      }
    });
  }

  String _generateCodeVerifier() {
    final random = Random.secure();
    final values = List<int>.generate(32, (i) => random.nextInt(256));
    return base64UrlEncode(values).replaceAll('=', '');
  }

  String _generateCodeChallenge(String verifier) {
    final bytes = utf8.encode(verifier);
    final digest = sha256.convert(bytes);
    return base64UrlEncode(digest.bytes).replaceAll('=', '');
  }

  Future<void> _loginAndEnroll() async {
    print('DEBUG: _loginAndEnroll started');
    setState(() {
      _loggingIn = true;
      _status = 'Fetching hub info...';
    });

    HttpServer? server;

    try {
      final hubUrl = _hubController.text.trim();
      print('DEBUG: Fetching hub info from $hubUrl');
      final infoJson = _samLib.fetchHubInfoJSON(hubUrl);
      print('DEBUG: Hub info JSON: $infoJson');
      if (infoJson == null) {
        throw Exception('Failed to fetch hub info');
      }

      final info = jsonDecode(infoJson);
      if (info['error'] != null) {
        throw Exception('Hub info error: ${info['error']}');
      }

      final issuer = info['oidcIssuer'];
      final clientId = info['clientId'];
      final audience = info['audience'];

      print('DEBUG: Issuer: $issuer, ClientId: $clientId, Audience: $audience');

      if (issuer == null || clientId == null) {
        throw Exception('Incomplete hub info received');
      }

      setState(() {
        _status = 'Discovering OIDC endpoints...';
      });

      // Simple OIDC discovery
      final discoveryUrl = '$issuer/.well-known/openid-configuration';
      print('DEBUG: Fetching OIDC config from $discoveryUrl');
      final discResponse = await http.get(Uri.parse(discoveryUrl));
      print('DEBUG: OIDC config response status: ${discResponse.statusCode}');
      if (discResponse.statusCode != 200) {
        throw Exception('Failed to discover OIDC endpoints');
      }
      final discData = jsonDecode(discResponse.body);
      final authUrl = discData['authorization_endpoint'];
      final tokenUrl = discData['token_endpoint'];

      print('DEBUG: AuthURL: $authUrl, TokenURL: $tokenUrl');

      if (authUrl == null || tokenUrl == null) {
        throw Exception('Missing endpoints in OIDC discovery');
      }

      // Start local server to capture callback
      int? selectedPort;
      for (final port in [13000, 13001, 13002]) {
        try {
          server = await HttpServer.bind(InternetAddress.anyIPv4, port);
          selectedPort = port;
          print('DEBUG: Bound local server to port $port (any IPv4)');
          break;
        } catch (e) {
          print('DEBUG: Failed to bind to port $port: $e');
        }
      }

      if (server == null || selectedPort == null) {
        throw Exception(
            'Could not bind local callback listener (ports 13000-13002 busy)');
      }

      final verifier = _generateCodeVerifier();
      final challenge = _generateCodeChallenge(verifier);
      final state = base64UrlEncode(
              List<int>.generate(16, (_) => Random.secure().nextInt(256)))
          .replaceAll('=', '');
      final redirectUri = 'http://127.0.0.1:$selectedPort/callback';

      final queryParams = {
        'response_type': 'code',
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': 'openid email profile',
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
      };
      if (audience != null && audience.isNotEmpty) {
        queryParams['audience'] = audience;
      }

      final uri = Uri.parse(authUrl).replace(queryParameters: queryParams);

      print('OIDC Login URL: $uri');
      print('Expecting callback on: $redirectUri');

      setState(() {
        _status = 'Opening browser for login...';
      });

      if (!await launchUrl(uri, mode: LaunchMode.platformDefault)) {
        throw Exception('Could not launch login URL');
      }

      print('Waiting for callback on local server...');

      String? code;
      String? receivedState;

      await for (final request in server) {
        print('DEBUG: Received request: ${request.requestedUri}');

        if (request.requestedUri.path == '/callback') {
          final query = request.requestedUri.queryParameters;
          receivedState = query['state'];
          code = query['code'];

          print('DEBUG: Callback state: $receivedState, code: $code');

          if (receivedState != state) {
            print('DEBUG: State mismatch. Expected $state, got $receivedState');
            request.response.statusCode = 400;
            request.response.write('Invalid state parameter');
            await request.response.close();
            break;
          }

          if (code == null) {
            print('DEBUG: No code in callback');
            request.response.statusCode = 400;
            request.response.write('No code received');
            await request.response.close();
            break;
          }

          request.response.headers.contentType = ContentType.html;
          request.response.write(
              '<html><body><h1>Authorization successful!</h1><p>You can close this window and return to the app.</p></body></html>');
          await request.response.close();
          print('DEBUG: Callback handled successfully');
          break; // Success
        } else {
          print(
              'DEBUG: Ignoring non-callback request: ${request.requestedUri.path}');
          request.response.statusCode = 404;
          await request.response.close();
        }
      }

      await server.close();

      if (receivedState != state) {
        throw Exception('Invalid state parameter received');
      }

      if (code == null) {
        throw Exception('No code received');
      }

      setState(() {
        _status = 'Exchanging code for token...';
      });

      final tokenResponse = await http.post(
        Uri.parse(tokenUrl),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'grant_type': 'authorization_code',
          'client_id': clientId,
          'code': code,
          'redirect_uri': redirectUri,
          'code_verifier': verifier,
        },
      );

      if (tokenResponse.statusCode != 200) {
        throw Exception('Token exchange failed: ${tokenResponse.body}');
      }

      final tokenData = jsonDecode(tokenResponse.body);
      final jwt = tokenData['id_token'] ?? tokenData['access_token'];

      if (jwt == null) {
        throw Exception('No token received');
      }

      setState(() {
        _jwtController.text = jwt;
        _status = 'Token obtained! Enrolling...';
      });

      await _enroll();
    } catch (e) {
      setState(() {
        _status = 'Login/Enrollment failed: $e';
      });
    } finally {
      await server?.close();
      setState(() {
        _loggingIn = false;
      });
    }
  }

  Future<void> _startDeviceLogin() async {
    setState(() {
      _loggingIn = true;
      _status = 'Fetching hub info for device login...';
    });

    try {
      final hubUrl = _hubController.text.trim();
      print('DEBUG: Device Login: Fetching hub info from $hubUrl');
      final infoJson = _samLib.fetchHubInfoJSON(hubUrl);
      if (infoJson == null) throw Exception('Failed to fetch hub info');

      final info = jsonDecode(infoJson);
      if (info['error'] != null)
        throw Exception('Hub info error: ${info['error']}');

      final issuer = info['oidcIssuer'];
      final clientId = info['clientId'];
      final audience = info['audience'];

      if (issuer == null || clientId == null) {
        throw Exception('Incomplete hub info received');
      }

      // OIDC discovery
      final discoveryUrl = '$issuer/.well-known/openid-configuration';
      final discResponse = await http.get(Uri.parse(discoveryUrl));
      if (discResponse.statusCode != 200)
        throw Exception('Failed to discover OIDC endpoints');

      final discData = jsonDecode(discResponse.body);
      final deviceAuthUrl = discData['device_authorization_endpoint'];
      final tokenUrl = discData['token_endpoint'];

      if (deviceAuthUrl == null) {
        throw Exception('Device Authorization not supported by Issuer');
      }

      print('DEBUG: Device Auth Endpoint: $deviceAuthUrl');

      // 1. Request Device Code
      final deviceCodeResp = await http.post(
        Uri.parse(deviceAuthUrl),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'client_id': clientId,
          'scope': 'openid email profile',
          if (audience != null && audience.isNotEmpty) 'audience': audience,
        },
      );

      if (deviceCodeResp.statusCode != 200) {
        throw Exception('Failed to get device code: ${deviceCodeResp.body}');
      }

      final deviceData = jsonDecode(deviceCodeResp.body);
      final deviceCode = deviceData['device_code'];
      final userCode = deviceData['user_code'];
      final verificationUri = deviceData['verification_uri_complete'] ??
          deviceData['verification_uri'];
      int interval = deviceData['interval'] ?? 5; // seconds

      print('DEBUG: User Code: $userCode');
      print('DEBUG: Verification URI: $verificationUri');

      // 2. Show UI
      _devicePollingActive = true;
      _showDeviceCodeDialog(userCode, verificationUri);

      // 3. Start Polling
      _pollForDeviceToken(tokenUrl, clientId, deviceCode, interval);
    } catch (e) {
      setState(() {
        _status = 'Device Login failed: $e';
        _loggingIn = false;
      });
    }
  }

  Future<void> _pollForDeviceToken(
      String tokenUrl, String clientId, String deviceCode, int interval) async {
    print('DEBUG: Starting device token polling...');
    bool polling = true;
    while (polling && _devicePollingActive) {
      await Future.delayed(Duration(seconds: interval));

      if (!_devicePollingActive) break;

      try {
        final response = await http.post(
          Uri.parse(tokenUrl),
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': deviceCode,
            'client_id': clientId,
          },
        );

        if (response.statusCode == 200) {
          final data = jsonDecode(response.body);
          final jwt = data['id_token'] ?? data['access_token'];
          if (jwt != null) {
            setState(() {
              _jwtController.text = jwt;
              _status = 'Token obtained via Device Flow! Enrolling...';
            });
            await _enroll();
            polling = false;
            _devicePollingActive = false;
            if (mounted && Navigator.canPop(context)) {
              Navigator.pop(context);
            }
          }
        } else {
          final errorData = jsonDecode(response.body);
          final error = errorData['error'];

          if (error == 'authorization_pending') {
            print('DEBUG: Authorization pending...');
          } else if (error == 'slow_down') {
            print('DEBUG: Slow down requested');
            interval += 5; // Slow down
          } else {
            throw Exception('Device login error: $error');
          }
        }
      } catch (e) {
        print('DEBUG: Polling error: $e');
        setState(() {
          _status = 'Polling failed: $e';
        });
        polling = false;
        _devicePollingActive = false;
        if (mounted && Navigator.canPop(context)) {
          Navigator.pop(context);
        }
      }
    }

    setState(() {
      _loggingIn = false;
    });
  }

  void _showDeviceCodeDialog(String userCode, String verificationUri) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('Device Login'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('Scan this QR code or visit the URL below:'),
                const SizedBox(height: 10),
                SizedBox(
                  width: 200,
                  height: 200,
                  child: QrImageView(
                    data: verificationUri,
                    version: QrVersions.auto,
                    backgroundColor: Colors.white,
                  ),
                ),
                const SizedBox(height: 20),
                SelectableText(
                  verificationUri,
                  style: const TextStyle(
                      fontWeight: FontWeight.bold, color: Colors.blue),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 20),
                const Text('And enter this code:'),
                SelectableText(
                  userCode,
                  style: const TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 2),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () async {
                final uri = Uri.parse(verificationUri);
                if (await canLaunchUrl(uri)) {
                  await launchUrl(uri, mode: LaunchMode.externalApplication);
                }
              },
              child: const Text('Open Browser (This Device)'),
            ),
            TextButton(
              onPressed: () {
                _devicePollingActive = false;
                Navigator.of(context).pop();
                setState(() {
                  _loggingIn = false;
                  _status = 'Device login cancelled by user';
                });
              },
              child: const Text('Cancel'),
            ),
          ],
        );
      },
    );
  }

  Future<void> _enroll() async {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';
    final err = _samLib.enroll(
      dataDir,
      _hubController.text,
      _jwtController.text,
      true, // allowLoopback
    );

    setState(() {
      if (err != null) {
        _status = 'Enrollment failed: $err';
      } else {
        _status = 'Enrollment successful!';
        _isEnrolled = true; // Switch to Dashboard
      }
    });
  }

  void _startPolling() {
    _pollingTimer?.cancel();
    _pollingTimer = Timer.periodic(const Duration(seconds: 3), (timer) {
      if (!_running) {
        timer.cancel();
        return;
      }
      _updateMeshInfo();
    });
    _updateMeshInfo(); // Run once immediately
  }

  void _updateMeshInfo() {
    final infoJson = _samLib.getMeshInfo();
    if (infoJson != null) {
      try {
        final info = jsonDecode(infoJson);
        if (info['error'] == null) {
          setState(() {
            _connectedPeers = info['connected_peers'] ?? 0;
            _dhtSize = info['dht_size'] ?? 0;
            if (info['node_id'] != null) {
              _nodeID = info['node_id'];
            }
          });
        }
      } catch (e) {
        print('DEBUG: Error parsing mesh info: $e');
      }
    }
  }

  Future<void> _start() async {
    final appDir = await getApplicationDocumentsDirectory();
    final dataDir = '${appDir.path}/sam_data';

    final err = _samLib.start({
      'dataDir': dataDir,
      'hubURL': _hubController.text,
      'meshID': 'public-mesh',
      'bindAddr': '127.0.0.1:5005', // sidecar port inside phone
      'apiToken': _tokenController.text,
      'allowLoopback': true,
      'enableRelay': false,
    });

    if (err != null) {
      setState(() {
        _status = 'Start failed: $err';
      });
      return;
    }

    // Start Android Foreground Service to keep process alive
    try {
      await _exposeChannel.invokeMethod('startBackgroundService');
    } catch (e) {
      print('DEBUG: Failed to start background service: $e');
      // Non-fatal, but node might be killed in background
    }

    setState(() {
      _running = true;
      _status = 'Running';
      _nodeID = _samLib.getNodeID() ?? 'unknown';
    });
    
    // Start embedded MCP server
    await _embeddedMcpServer.start(
      goSidecarPort: '5005',
      apiToken: _tokenController.text,
    );

    _startPolling();
  }

  void _stop() {
    _pollingTimer?.cancel();
    _embeddedMcpServer.stop();
    final err = _samLib.stop();
    
    // Stop Android Foreground Service
    try {
      _exposeChannel.invokeMethod('stopBackgroundService');
    } catch (e) {
      print('DEBUG: Failed to stop background service: $e');
    }

    setState(() {
      if (err != null) {
        _status = 'Stop failed: $err';
      } else {
        _running = false;
        _status = 'Stopped';
        _connectedPeers = 0;
        _dhtSize = 0;
      }
    });
  }

  Future<void> _unenroll() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unenroll Node'),
        content: const Text(
            'Are you sure you want to unenroll? This will delete your local identity and disconnect you from the mesh.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Unenroll', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirm == true) {
      if (_running) {
        _stop();
      }
      final appDir = await getApplicationDocumentsDirectory();
      final dataDir = '${appDir.path}/sam_data';
      try {
        final dir = Directory(dataDir);
        if (await dir.exists()) {
          await dir.delete(recursive: true);
        }
        setState(() {
          _isEnrolled = false;
          _status = 'Unenrolled';
          _nodeID = '';
        });
      } catch (e) {
        setState(() {
          _status = 'Failed to unenroll: $e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SAM Node Mobile')),
      body: _isEnrolled == true
          ? (_selectedTab == 0 ? _buildDashboardView() : _buildServicesView())
          : _buildBody(),
      bottomNavigationBar: _isEnrolled == true
          ? BottomNavigationBar(
              currentIndex: _selectedTab,
              onTap: (index) {
                setState(() {
                  _selectedTab = index;
                });
              },
              items: const [
                BottomNavigationBarItem(
                  icon: Icon(Icons.dashboard),
                  label: 'Dashboard',
                ),
                BottomNavigationBarItem(
                  icon: Icon(Icons.electrical_services),
                  label: 'Services',
                ),
              ],
            )
          : null,
    );
  }

  Widget _buildBody() {
    if (_isEnrolled == null) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_isEnrolled == false) {
      return _buildEnrollmentView();
    }

    return _buildDashboardView();
  }

  Widget _buildServicesView() {
      final bool isRunning = _running;
      return SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Expose Services Section
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Expose Local Services to Mesh',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                    const SizedBox(height: 10),
                    SwitchListTile(
                      title: const Text('Battery Status'),
                      subtitle: const Text('Share battery level and charging state with mesh peers'),
                      value: _exposeBattery,
                      onChanged: (bool value) async {
                        setState(() {
                          _exposeBattery = value;
                        });
                        try {
                          await _exposeChannel.invokeMethod('setExposeBattery', {'enabled': value});
                        } catch (e) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text('Failed to toggle battery exposure: $e')),
                          );
                        }
                      },
                      secondary: const Icon(Icons.battery_std),
                    ),
                    SwitchListTile(
                      title: const Text('Location'),
                      subtitle: const Text('Share coarse location with mesh peers'),
                      value: _exposeLocation,
                      onChanged: (bool value) async {
                        setState(() {
                          _exposeLocation = value;
                        });
                        try {
                          await _exposeChannel.invokeMethod('setExposeLocation', {'enabled': value});
                        } catch (e) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text('Failed to toggle location exposure: $e')),
                          );
                        }
                      },
                      secondary: const Icon(Icons.location_on),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 20),

            // External MCP Bridging Section
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Bridge External Local MCP to Mesh',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                    const SizedBox(height: 10),
                    TextFormField(
                      controller: _externalMcpUrlController,
                      decoration: const InputDecoration(
                        labelText: 'External MCP Server URL',
                        hintText: 'http://127.0.0.1:8080',
                        border: OutlineInputBorder(),
                      ),
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: TextFormField(
                            controller: _externalMcpNameController,
                            decoration: const InputDecoration(
                              labelText: 'Service Name',
                              hintText: 'android-remote',
                              border: OutlineInputBorder(),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        ElevatedButton(
                          onPressed: !isRunning ? null : () async {
                            if (_externalMcpRegistered) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Unregister not fully supported yet in UI')),
                              );
                            } else {
                              final success = await SamDartMcpServer.registerService(
                                goSidecarPort: '5005',
                                apiToken: _tokenController.text,
                                serviceName: _externalMcpNameController.text,
                                targetUrl: _externalMcpUrlController.text,
                                description: _externalMcpDescController.text,
                              );
                              if (success) {
                                setState(() {
                                  _externalMcpRegistered = true;
                                });
                                ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(content: Text('External MCP Registered!')),
                                );
                              } else {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(content: Text('Failed to register external MCP')),
                                );
                              }
                            }
                          },
                          child: Text(_externalMcpRegistered ? 'Registered' : 'Register'),
                        ),
                      ],
                    ),
                     const SizedBox(height: 10),
                     TextFormField(
                      controller: _externalMcpDescController,
                      decoration: const InputDecoration(
                        labelText: 'Description',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      );
  }

  Widget _buildEnrollmentView() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Welcome to SAM',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center),
          const SizedBox(height: 20),
          const Text('Please enroll your node to join the mesh.',
              textAlign: TextAlign.center),
          const SizedBox(height: 30),
          TextField(
            controller: _hubController,
            decoration: const InputDecoration(
              labelText: 'Hub URL',
              border: OutlineInputBorder(),
              hintText: 'https://bananas.sam-mesh.dev',
            ),
          ),
          const SizedBox(height: 20),
          ElevatedButton.icon(
            onPressed: _loggingIn ? null : _loginAndEnroll,
            icon: _loggingIn
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.login),
            label: const Text('Login & Enroll (Browser)'),
            style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16)),
          ),
          const SizedBox(height: 10),
          ElevatedButton.icon(
            onPressed: _loggingIn ? null : _startDeviceLogin,
            icon: const Icon(Icons.tv),
            label: const Text('Device Login (TV / Other Device)'),
            style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16)),
          ),
          const SizedBox(height: 30),
          if (_status.isNotEmpty &&
              _status != 'Enrolled' &&
              _status != 'Unenrolled')
            Card(
              color: Colors.grey.shade100,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    Text('Status: $_status',
                        style: const TextStyle(fontStyle: FontStyle.italic)),
                    const SizedBox(height: 10),
                    ElevatedButton(
                      onPressed: () async {
                        try {
                          final model = FirebaseAI.googleAI().generativeModel(
                            model: 'gemini-2.5-flash',
                          );
                          print('DEBUG: Model initialized: ${model.hashCode}');
                          setState(() {
                            _status = 'Debug: Model initialized';
                          });
                        } catch (e) {
                          setState(() {
                            _status = 'API Error: $e';
                          });
                        }
                      },
                      child: const Text('Debug API Connection'),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildDashboardView() {
    final bool isRunning = _running;
    final Color statusColor = isRunning ? Colors.green : Colors.grey;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Status Card
          Card(
            elevation: 4,
            child: Padding(
              padding: const EdgeInsets.all(20.0),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Container(
                        width: 16,
                        height: 16,
                        decoration: BoxDecoration(
                          color: statusColor,
                          shape: BoxShape.circle,
                          boxShadow: [
                            if (isRunning)
                              BoxShadow(
                                color: Colors.green.withOpacity(0.5),
                                spreadRadius: 4,
                                blurRadius: 4,
                              )
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      Text(
                        isRunning ? 'Node is Running' : 'Node is Stopped',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                          color: isRunning
                              ? Colors.green.shade700
                              : Colors.grey.shade700,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Text('Mesh: public-mesh',
                      style: TextStyle(color: Colors.grey.shade600)),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),

          // Stats Grid
          Row(
            children: [
              Expanded(
                child: _buildStatCard(
                  icon: Icons.people,
                  title: 'Connected Peers',
                  value: '$_connectedPeers',
                  color: Colors.blue,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildStatCard(
                  icon: Icons.storage,
                  title: 'DHT Size',
                  value: '$_dhtSize',
                  color: Colors.purple,
                ),
              ),
            ],
          ),
          const SizedBox(height: 30),

          // Node Info
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Node ID',
                      style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  SelectableText(
                    _nodeID.isEmpty
                        ? 'Unknown (Start node to see ID)'
                        : _nodeID,
                    style:
                        const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 30),

          // Controls
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: isRunning ? null : _start,
                  icon: const Icon(Icons.play_arrow),
                  label: const Text('Start'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.green,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: isRunning ? _stop : null,
                  icon: const Icon(Icons.stop),
                  label: const Text('Stop'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.red,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Unenroll fallback
          TextButton.icon(
            onPressed: _unenroll,
            icon: const Icon(Icons.logout, color: Colors.red),
            label: const Text('Unenroll / Clear Identity',
                style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(
      {required IconData icon,
      required String title,
      required String value,
      required Color color}) {
    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Icon(icon, color: color, size: 30),
            const SizedBox(height: 10),
            Text(value,
                style:
                    const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
            const SizedBox(height: 5),
            Text(title,
                style: TextStyle(color: Colors.grey.shade600, fontSize: 12),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
