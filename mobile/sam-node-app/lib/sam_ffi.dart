import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';

// FFI signatures
typedef StartNodeC = ffi.Pointer<Utf8> Function(ffi.Pointer<Utf8> configJSON);
typedef StartNodeDart = ffi.Pointer<Utf8> Function(ffi.Pointer<Utf8> configJSON);

typedef StopNodeC = ffi.Pointer<Utf8> Function();
typedef StopNodeDart = ffi.Pointer<Utf8> Function();

typedef GetNodeIDC = ffi.Pointer<Utf8> Function();
typedef GetNodeIDDart = ffi.Pointer<Utf8> Function();

typedef EnrollNodeC = ffi.Pointer<Utf8> Function(
    ffi.Pointer<Utf8> dataDir,
    ffi.Pointer<Utf8> hubURL,
    ffi.Pointer<Utf8> jwt,
    ffi.Int8 allowLoopback);
typedef EnrollNodeDart = ffi.Pointer<Utf8> Function(
    ffi.Pointer<Utf8> dataDir,
    ffi.Pointer<Utf8> hubURL,
    ffi.Pointer<Utf8> jwt,
    int allowLoopback);

typedef FetchHubInfoJSONC = ffi.Pointer<Utf8> Function(ffi.Pointer<Utf8> hubURL);
typedef FetchHubInfoJSONDart = ffi.Pointer<Utf8> Function(ffi.Pointer<Utf8> hubURL);

typedef IsEnrolledC = ffi.Int8 Function(ffi.Pointer<Utf8> dataDir);
typedef IsEnrolledDart = int Function(ffi.Pointer<Utf8> dataDir);

typedef GetMeshInfoC = ffi.Pointer<Utf8> Function();
typedef GetMeshInfoDart = ffi.Pointer<Utf8> Function();

typedef FreeStringC = ffi.Void Function(ffi.Pointer<Utf8> str);
typedef FreeStringDart = void Function(ffi.Pointer<Utf8> str);

class SamNodeLib {
  late ffi.DynamicLibrary _dylib;
  late StartNodeDart _startNode;
  late StopNodeDart _stopNode;
  late GetNodeIDDart _getNodeID;
  late EnrollNodeDart _enrollNode;
  late FetchHubInfoJSONDart _fetchHubInfoJSON;
  late IsEnrolledDart _isEnrolled;
  late GetMeshInfoDart _getMeshInfo;
  late FreeStringDart _freeString;

  SamNodeLib() {
    if (Platform.isAndroid) {
      _dylib = ffi.DynamicLibrary.open('libsam.so');
    } else if (Platform.isIOS || Platform.isMacOS) {
      _dylib = ffi.DynamicLibrary.process();
    } else {
      _dylib = ffi.DynamicLibrary.open('libsam.so'); // fallback
    }

    _startNode = _dylib.lookupFunction<StartNodeC, StartNodeDart>('StartNode');
    _stopNode = _dylib.lookupFunction<StopNodeC, StopNodeDart>('StopNode');
    _getNodeID = _dylib.lookupFunction<GetNodeIDC, GetNodeIDDart>('GetNodeID');
    _enrollNode = _dylib.lookupFunction<EnrollNodeC, EnrollNodeDart>('EnrollNode');
    _fetchHubInfoJSON = _dylib.lookupFunction<FetchHubInfoJSONC, FetchHubInfoJSONDart>('FetchHubInfoJSON');
    _isEnrolled = _dylib.lookupFunction<IsEnrolledC, IsEnrolledDart>('IsEnrolled');
    _getMeshInfo = _dylib.lookupFunction<GetMeshInfoC, GetMeshInfoDart>('GetMeshInfo');
    _freeString = _dylib.lookupFunction<FreeStringC, FreeStringDart>('FreeString');
  }

  String? start(Map<String, dynamic> config) {
    final configJSON = jsonEncode(config);
    final cConfig = configJSON.toNativeUtf8();
    final cErr = _startNode(cConfig);
    calloc.free(cConfig);

    if (cErr.address == 0) return null;
    final goErr = cErr.toDartString();
    _freeString(cErr);
    return goErr;
  }

  String? stop() {
    final cErr = _stopNode();
    if (cErr.address == 0) return null;
    final goErr = cErr.toDartString();
    _freeString(cErr);
    return goErr;
  }

  String? getNodeID() {
    final cID = _getNodeID();
    if (cID.address == 0) return null;
    final goID = cID.toDartString();
    _freeString(cID);
    return goID;
  }

  String? enroll(String dataDir, String hubURL, String jwt, bool allowLoopback) {
    final cDataDir = dataDir.toNativeUtf8();
    final cHubURL = hubURL.toNativeUtf8();
    final cJWT = jwt.toNativeUtf8();
    final cAllowLoopback = allowLoopback ? 1 : 0;

    final cErr = _enrollNode(cDataDir, cHubURL, cJWT, cAllowLoopback);

    calloc.free(cDataDir);
    calloc.free(cHubURL);
    calloc.free(cJWT);

    if (cErr.address == 0) return null;
    final goErr = cErr.toDartString();
    _freeString(cErr);
    return goErr;
  }

  String? fetchHubInfoJSON(String hubURL) {
    final cHubURL = hubURL.toNativeUtf8();
    final cResult = _fetchHubInfoJSON(cHubURL);
    calloc.free(cHubURL);

    if (cResult.address == 0) return null;
    final goResult = cResult.toDartString();
    _freeString(cResult);
    return goResult;
  }

  bool isEnrolled(String dataDir) {
    final cDataDir = dataDir.toNativeUtf8();
    final result = _isEnrolled(cDataDir);
    calloc.free(cDataDir);
    return result != 0;
  }

  String? getMeshInfo() {
    final cResult = _getMeshInfo();
    if (cResult.address == 0) return null;
    final goResult = cResult.toDartString();
    _freeString(cResult);
    return goResult;
  }
}
