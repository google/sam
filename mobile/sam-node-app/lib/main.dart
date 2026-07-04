import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'sam_ffi.dart';

void main() {
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
  final _hubController = TextEditingController(text: 'https://bananas.sam-mesh.dev');
  final _jwtController = TextEditingController();
  final _tokenController = TextEditingController(text: 'secret-token');

  late SamNodeLib _samLib;
  bool _running = false;
  String _status = 'Disconnected';
  String _nodeID = '';

  @override
  void initState() {
    super.initState();
    _samLib = SamNodeLib();
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
        _status = 'Enrollment successful! You can now start the node.';
      }
    });
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

    setState(() {
      _running = true;
      _status = 'Running';
      _nodeID = _samLib.getNodeID() ?? 'unknown';
    });
  }

  void _stop() {
    final err = _samLib.stop();
    setState(() {
      if (err != null) {
        _status = 'Stop failed: $err';
      } else {
        _running = false;
        _status = 'Stopped';
        _nodeID = '';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SAM Node Mobile')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _hubController,
              decoration: const InputDecoration(labelText: 'Hub URL / Address'),
            ),
            TextField(
              controller: _jwtController,
              decoration: const InputDecoration(labelText: 'Enrollment JWT'),
            ),
            TextField(
              controller: _tokenController,
              decoration: const InputDecoration(labelText: 'Local API Token'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _enroll,
              child: const Text('Enroll Node'),
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _running ? null : _start,
                    child: const Text('Start Node'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: ElevatedButton(
                    onPressed: _running ? _stop : null,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.shade100,
                    ),
                    child: const Text('Stop Node'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 30),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Status: $_status', style: const TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 10),
                    Text('Node ID: $_nodeID', style: const TextStyle(fontFamily: 'monospace')),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
