// 独立测试脚本 - 仅测试 VLESS 解析核心逻辑，不依赖 Flutter
// 运行方式: dart run test/vless_standalone_test.dart

import 'dart:convert';

// ===== 从 vless.dart 内联核心逻辑 (脱离 fl_clash 依赖) =====

enum VlessNetwork {
  tcp, ws, grpc, h2, http;

  static VlessNetwork fromString(String? value) {
    return VlessNetwork.values.firstWhere(
      (e) => e.name == value,
      orElse: () => VlessNetwork.tcp,
    );
  }

  String get clashValue => switch (this) {
    VlessNetwork.http => 'h2',
    _ => name,
  };
}

enum VlessSecurity {
  none, tls, reality;

  static VlessSecurity fromString(String? value) {
    return VlessSecurity.values.firstWhere(
      (e) => e.name == value,
      orElse: () => VlessSecurity.none,
    );
  }
}

enum VlessFlow {
  none, xtlsRprxVision, xtlsRprxVisionUdp443;

  static VlessFlow fromString(String? value) {
    switch (value) {
      case 'xtls-rprx-vision': return VlessFlow.xtlsRprxVision;
      case 'xtls-rprx-vision-udp443': return VlessFlow.xtlsRprxVisionUdp443;
      default: return VlessFlow.none;
    }
  }

  String? toConfigValue() {
    switch (this) {
      case VlessFlow.none: return null;
      case VlessFlow.xtlsRprxVision: return 'xtls-rprx-vision';
      case VlessFlow.xtlsRprxVisionUdp443: return 'xtls-rprx-vision-udp443';
    }
  }
}

class VlessConfig {
  final String uuid;
  final String server;
  final int port;
  final String name;
  final VlessNetwork network;
  final VlessSecurity security;
  final String? sni;
  final String? peer;
  final String? fingerprint;
  final List<String>? alpn;
  final bool allowInsecure;
  final VlessFlow flow;
  final String? path;
  final String? host;
  final String? serviceName;
  final String? grpcMode;
  final String? publicKey;
  final String? shortId;
  final String? serverName;

  VlessConfig({
    required this.uuid, required this.server, required this.port,
    this.name = '', this.network = VlessNetwork.tcp,
    this.security = VlessSecurity.none, this.sni, this.peer,
    this.fingerprint, this.alpn, this.allowInsecure = false,
    this.flow = VlessFlow.none, this.path, this.host,
    this.serviceName, this.grpcMode, this.publicKey,
    this.shortId, this.serverName,
  });

  factory VlessConfig.fromUri(String uriString) {
    final content = _tryDecodeBase64(uriString);
    final uri = Uri.parse(content);
    if (uri.scheme != 'vless') {
      throw FormatException('不是有效的 VLESS 链接: scheme="${uri.scheme}"');
    }
    final uuid = uri.userInfo;
    if (uuid.isEmpty) throw const FormatException('VLESS 链接缺少 UUID');
    final server = uri.host;
    if (server.isEmpty) throw const FormatException('VLESS 链接缺少服务器地址');
    final port = uri.hasPort ? uri.port : 443;
    final name = uri.fragment.isNotEmpty
        ? Uri.decodeComponent(uri.fragment)
        : '$server:$port';
    final params = uri.queryParameters;
    final alpnStr = params['alpn'];
    final alpn = alpnStr != null && alpnStr.isNotEmpty
        ? alpnStr.split(',').where((s) => s.isNotEmpty).toList()
        : null;
    return VlessConfig(
      uuid: uuid, server: server, port: port, name: name,
      network: VlessNetwork.fromString(params['type']),
      security: VlessSecurity.fromString(params['security']),
      sni: params['sni'], peer: params['peer'],
      fingerprint: params['fp'], alpn: alpn,
      allowInsecure: params['allowInsecure'] == '1' || params['allowInsecure'] == 'true',
      flow: VlessFlow.fromString(params['flow']),
      path: params['path'], host: params['host'],
      serviceName: params['serviceName'], grpcMode: params['mode'],
      publicKey: params['pbk'], shortId: params['sid'],
      serverName: params['sni'] ?? params['peer'],
    );
  }

  static String _tryDecodeBase64(String uriString) {
    const prefix = 'vless://';
    if (!uriString.startsWith(prefix)) return uriString;
    final body = uriString.substring(prefix.length);
    if (!body.contains('@') && !body.contains(':')) {
      try {
        final normalized = base64.normalize(body);
        final decoded = utf8.decode(base64.decode(normalized));
        return 'vless://$decoded';
      } catch (_) {}
    }
    return uriString;
  }

  Map<String, dynamic> toClashProxy() {
    final proxy = <String, dynamic>{
      'name': name, 'type': 'vless', 'server': server,
      'port': port, 'uuid': uuid, 'udp': true,
      'network': network.clashValue,
    };
    final flowValue = flow.toConfigValue();
    if (flowValue != null) {
      proxy['client-fingerprint'] = fingerprint ?? 'chrome';
      proxy['flow'] = flowValue;
    }
    _applyTlsConfig(proxy);
    _applyNetworkConfig(proxy);
    return proxy;
  }

  void _applyTlsConfig(Map<String, dynamic> proxy) {
    switch (security) {
      case VlessSecurity.tls:
        proxy['tls'] = true;
        if (sni != null && sni!.isNotEmpty) proxy['servername'] = sni;
        if (fingerprint != null && fingerprint!.isNotEmpty) proxy['client-fingerprint'] = fingerprint;
        if (alpn != null && alpn!.isNotEmpty) proxy['alpn'] = alpn;
        if (allowInsecure) proxy['skip-cert-verify'] = true;
        break;
      case VlessSecurity.reality:
        proxy['tls'] = true;
        if (sni != null && sni!.isNotEmpty) proxy['servername'] = sni;
        if (fingerprint != null && fingerprint!.isNotEmpty) proxy['client-fingerprint'] = fingerprint;
        if (alpn != null && alpn!.isNotEmpty) proxy['alpn'] = alpn;
        final realityOpts = <String, dynamic>{};
        if (publicKey != null && publicKey!.isNotEmpty) realityOpts['public-key'] = publicKey;
        if (shortId != null && shortId!.isNotEmpty) realityOpts['short-id'] = shortId;
        if (serverName != null && serverName!.isNotEmpty) realityOpts['server-name'] = serverName;
        if (realityOpts.isNotEmpty) proxy['reality-opts'] = realityOpts;
        break;
      case VlessSecurity.none:
        proxy['tls'] = false;
        break;
    }
  }

  void _applyNetworkConfig(Map<String, dynamic> proxy) {
    switch (network) {
      case VlessNetwork.ws:
        final wsOpts = <String, dynamic>{};
        if (path != null && path!.isNotEmpty) wsOpts['path'] = path;
        if (host != null && host!.isNotEmpty) wsOpts['headers'] = {'Host': host};
        if (wsOpts.isNotEmpty) proxy['ws-opts'] = wsOpts;
        break;
      case VlessNetwork.grpc:
        final grpcOpts = <String, dynamic>{};
        if (serviceName != null && serviceName!.isNotEmpty) grpcOpts['grpc-service-name'] = serviceName;
        if (grpcOpts.isNotEmpty) proxy['grpc-opts'] = grpcOpts;
        break;
      case VlessNetwork.h2:
      case VlessNetwork.http:
        final h2Opts = <String, dynamic>{};
        if (path != null && path!.isNotEmpty) h2Opts['path'] = path;
        if (host != null && host!.isNotEmpty) h2Opts['host'] = [host];
        if (h2Opts.isNotEmpty) proxy['h2-opts'] = h2Opts;
        break;
      case VlessNetwork.tcp:
        break;
    }
  }
}

// ===== 协议检测 =====
bool isProtocolLink(String input) {
  final trimmed = input.trim();
  return ['vless'].any((s) => trimmed.startsWith('$s://'));
}

// ===== 测试框架 =====
int _passed = 0;
int _failed = 0;
String _currentGroup = '';

void group(String name, void Function() body) {
  _currentGroup = name;
  print('\n  $name');
  body();
}

void test(String name, void Function() body) {
  try {
    body();
    _passed++;
    print('    ✓ $name');
  } catch (e) {
    _failed++;
    print('    ✗ $name');
    print('      错误: $e');
  }
}

void expect(dynamic actual, dynamic expected) {
  if (actual != expected) {
    throw '期望 $expected, 实际 $actual';
  }
}

void expectThrows<T>(void Function() body) {
  try {
    body();
    throw Exception('期望抛出异常，但没有抛出');
  } on Exception catch (e) {
    // 如果是"期望抛出异常"的 Exception，说明 body 没抛异常，测试失败
    if (e.toString().contains('期望抛出异常')) rethrow;
    // 否则 body 抛出了异常，检查类型
    if (e is T) return; // 类型匹配，测试通过
    throw Exception('期望抛出 $T，但抛出了 ${e.runtimeType}: $e');
  } catch (e) {
    // 非 Exception 类型的错误 (如 FormatException 是 Exception 的子类，会走上面的分支)
    throw Exception('意外错误: $e');
  }
}

// ===== 测试用例 =====
void main() {
  print('VLESS 协议解析器测试');
  print('=' * 50);

  group('基础解析', () {
    test('解析基础 VLESS+TCP+TLS 链接', () {
      final c = VlessConfig.fromUri(
        'vless://b0cbdbe6-2fce-4006-878e-b9c4e8a4f7fb@example.com:443?security=tls&type=tcp&sni=example.com&fp=chrome#TestNode',
      );
      expect(c.uuid, 'b0cbdbe6-2fce-4006-878e-b9c4e8a4f7fb');
      expect(c.server, 'example.com');
      expect(c.port, 443);
      expect(c.name, 'TestNode');
      expect(c.security, VlessSecurity.tls);
      expect(c.network, VlessNetwork.tcp);
      expect(c.sni, 'example.com');
      expect(c.fingerprint, 'chrome');
    });

    test('解析无名称链接 (使用 server:port)', () {
      final c = VlessConfig.fromUri('vless://uuid@server.test:8443?type=tcp&security=none');
      expect(c.name, 'server.test:8443');
    });

    test('解析 URL 编码的节点名称', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@server.test:443?type=tcp&security=none#%E9%A6%99%E6%B8%AF%20%E8%8A%82%E7%82%B9',
      );
      expect(c.name, '香港 节点');
    });

    test('无效 scheme 抛出异常', () {
      expectThrows<FormatException>(() => VlessConfig.fromUri('http://example.com:443'));
    });

    test('缺少 UUID 抛出异常', () {
      expectThrows<FormatException>(() => VlessConfig.fromUri('vless://example.com:443?type=tcp'));
    });
  });

  group('传输层解析', () {
    test('VLESS+WebSocket', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@ws.server:443?type=ws&security=tls&path=%2Fws&sni=ws.server&host=ws.server&fp=chrome#WS',
      );
      expect(c.network, VlessNetwork.ws);
      expect(c.path, '/ws');
      expect(c.host, 'ws.server');
    });

    test('VLESS+gRPC', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@grpc.server:443?type=grpc&security=tls&serviceName=myservice&mode=multi&sni=g#G',
      );
      expect(c.network, VlessNetwork.grpc);
      expect(c.serviceName, 'myservice');
      expect(c.grpcMode, 'multi');
    });

    test('VLESS+H2', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@h2.server:443?type=h2&security=tls&path=%2Fh2&host=h2.server&sni=h2.server#H2',
      );
      expect(c.network, VlessNetwork.h2);
      expect(c.path, '/h2');
      expect(c.host, 'h2.server');
    });

    test('默认传输层为 TCP', () {
      final c = VlessConfig.fromUri('vless://uuid@server:443?security=none#TCP');
      expect(c.network, VlessNetwork.tcp);
    });
  });

  group('安全层解析', () {
    test('TLS 完整配置', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=tls&sni=my.server&fp=firefox&alpn=h2,http/1.1&allowInsecure=1#TLS',
      );
      expect(c.security, VlessSecurity.tls);
      expect(c.sni, 'my.server');
      expect(c.fingerprint, 'firefox');
      expect(c.alpn!.length, 2);
      expect(c.alpn![0], 'h2');
      expect(c.alpn![1], 'http/1.1');
      expect(c.allowInsecure, true);
    });

    test('Reality 配置', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=abc123&sid=def456&flow=xtls-rprx-vision#R',
      );
      expect(c.security, VlessSecurity.reality);
      expect(c.publicKey, 'abc123');
      expect(c.shortId, 'def456');
      expect(c.flow, VlessFlow.xtlsRprxVision);
    });

    test('默认安全类型为 none', () {
      final c = VlessConfig.fromUri('vless://uuid@s:443?type=tcp#N');
      expect(c.security, VlessSecurity.none);
    });

    test('allowInsecure=true 字符串', () {
      final c = VlessConfig.fromUri('vless://uuid@s:443?type=tcp&security=tls&allowInsecure=true#I');
      expect(c.allowInsecure, true);
    });
  });

  group('流控解析', () {
    test('xtls-rprx-vision', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=k&sid=i&sni=sn#V',
      );
      expect(c.flow, VlessFlow.xtlsRprxVision);
      expect(c.flow.toConfigValue(), 'xtls-rprx-vision');
    });

    test('xtls-rprx-vision-udp443', () {
      final c = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=reality&flow=xtls-rprx-vision-udp443&pbk=k&sid=i&sni=sn#V',
      );
      expect(c.flow, VlessFlow.xtlsRprxVisionUdp443);
      expect(c.flow.toConfigValue(), 'xtls-rprx-vision-udp443');
    });

    test('默认流控为 none', () {
      final c = VlessConfig.fromUri('vless://uuid@s:443?type=tcp&security=none#N');
      expect(c.flow, VlessFlow.none);
      expect(c.flow.toConfigValue(), null);
    });
  });

  group('Clash 配置生成', () {
    test('基础 TCP+None', () {
      final p = VlessConfig.fromUri('vless://test-uuid@1.2.3.4:443?type=tcp&security=none#Basic').toClashProxy();
      expect(p['name'], 'Basic');
      expect(p['type'], 'vless');
      expect(p['server'], '1.2.3.4');
      expect(p['port'], 443);
      expect(p['uuid'], 'test-uuid');
      expect(p['udp'], true);
      expect(p['network'], 'tcp');
      expect(p['tls'], false);
    });

    test('TLS 配置', () {
      final p = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=tls&sni=my.server&fp=chrome&alpn=h2,http/1.1#TLS',
      ).toClashProxy();
      expect(p['tls'], true);
      expect(p['servername'], 'my.server');
      expect(p['client-fingerprint'], 'chrome');
      expect((p['alpn'] as List).length, 2);
    });

    test('Reality 含 reality-opts', () {
      final p = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=reality&sni=www.test.com&fp=chrome&pbk=mykey&sid=sid123&flow=xtls-rprx-vision#R',
      ).toClashProxy();
      expect(p['tls'], true);
      expect(p['flow'], 'xtls-rprx-vision');
      final ro = p['reality-opts'] as Map<String, dynamic>;
      expect(ro['public-key'], 'mykey');
      expect(ro['short-id'], 'sid123');
    });

    test('WebSocket 含 ws-opts', () {
      final p = VlessConfig.fromUri(
        'vless://uuid@s:443?type=ws&security=tls&path=%2Fws&host=custom.host&sni=s#WS',
      ).toClashProxy();
      expect(p['network'], 'ws');
      final wo = p['ws-opts'] as Map<String, dynamic>;
      expect(wo['path'], '/ws');
      expect((wo['headers'] as Map)['Host'], 'custom.host');
    });

    test('gRPC 含 grpc-opts', () {
      final p = VlessConfig.fromUri(
        'vless://uuid@s:443?type=grpc&security=tls&serviceName=svc&sni=s#G',
      ).toClashProxy();
      expect(p['network'], 'grpc');
      final go = p['grpc-opts'] as Map<String, dynamic>;
      expect(go['grpc-service-name'], 'svc');
    });

    test('H2 含 h2-opts', () {
      final p = VlessConfig.fromUri(
        'vless://uuid@s:443?type=h2&security=tls&path=%2Fh2&host=h.com&sni=s#H',
      ).toClashProxy();
      expect(p['network'], 'h2');
      final ho = p['h2-opts'] as Map<String, dynamic>;
      expect(ho['path'], '/h2');
      expect((ho['host'] as List)[0], 'h.com');
    });

    test('skip-cert-verify 仅在 allowInsecure=true 时设置', () {
      final insecure = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=tls&allowInsecure=1&sni=s#I',
      ).toClashProxy();
      final secure = VlessConfig.fromUri(
        'vless://uuid@s:443?type=tcp&security=tls&sni=s#S',
      ).toClashProxy();
      expect(insecure['skip-cert-verify'], true);
      expect(secure.containsKey('skip-cert-verify'), false);
    });

    test('http 传输层 network 值映射为 h2', () {
      final p = VlessConfig.fromUri(
        'vless://uuid@s:443?type=http&security=tls&path=%2Fp&host=h.com&sni=s#H',
      ).toClashProxy();
      expect(p['network'], 'h2');
    });
  });

  group('枚举测试', () {
    test('VlessNetwork.clashValue', () {
      expect(VlessNetwork.tcp.clashValue, 'tcp');
      expect(VlessNetwork.ws.clashValue, 'ws');
      expect(VlessNetwork.grpc.clashValue, 'grpc');
      expect(VlessNetwork.h2.clashValue, 'h2');
      expect(VlessNetwork.http.clashValue, 'h2');
    });

    test('VlessNetwork.fromString 未知值返回 tcp', () {
      expect(VlessNetwork.fromString('unknown'), VlessNetwork.tcp);
      expect(VlessNetwork.fromString(null), VlessNetwork.tcp);
    });

    test('VlessSecurity.fromString', () {
      expect(VlessSecurity.fromString('none'), VlessSecurity.none);
      expect(VlessSecurity.fromString('tls'), VlessSecurity.tls);
      expect(VlessSecurity.fromString('reality'), VlessSecurity.reality);
      expect(VlessSecurity.fromString('xtls'), VlessSecurity.none);
    });

    test('VlessFlow.toConfigValue', () {
      expect(VlessFlow.none.toConfigValue(), null);
      expect(VlessFlow.xtlsRprxVision.toConfigValue(), 'xtls-rprx-vision');
      expect(VlessFlow.xtlsRprxVisionUdp443.toConfigValue(), 'xtls-rprx-vision-udp443');
    });
  });

  group('协议检测', () {
    test('识别 vless://', () {
      expect(isProtocolLink('vless://uuid@server:443'), true);
    });

    test('不识别 HTTP URL', () {
      expect(isProtocolLink('https://example.com'), false);
    });

    test('不识别无关字符串', () {
      expect(isProtocolLink('hello'), false);
      expect(isProtocolLink(''), false);
    });

    test('处理前后空白', () {
      expect(isProtocolLink('  vless://uuid@server  '), true);
    });
  });

  // 打印结果
  print('\n${'=' * 50}');
  print('测试结果: $_passed 通过, $_failed 失败, 共 ${_passed + _failed} 个');
  if (_failed > 0) {
    print('存在失败的测试!');
    throw Exception('测试未全部通过');
  } else {
    print('全部通过!');
  }
}
