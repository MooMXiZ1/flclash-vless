// VLESS 协议解析器单元测试
//
// 运行方式: flutter test test/vless_test.dart
//
// 注意: 这些测试直接验证 VlessConfig 的解析逻辑和 Clash 配置生成，
// 不依赖完整的 FlClash 运行环境

import 'package:fl_clash/common/protocol/vless.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('VlessConfig.fromUri 基础解析', () {
    test('解析基础 VLESS+TCP+TLS 链接', () {
      const uri =
          'vless://b0cbdbe6-2fce-4006-878e-b9c4e8a4f7fb@example.com:443?security=tls&type=tcp&sni=example.com&fp=chrome#TestNode';

      final config = VlessConfig.fromUri(uri);

      expect(config.uuid, 'b0cbdbe6-2fce-4006-878e-b9c4e8a4f7fb');
      expect(config.server, 'example.com');
      expect(config.port, 443);
      expect(config.name, 'TestNode');
      expect(config.security, VlessSecurity.tls);
      expect(config.network, VlessNetwork.tcp);
      expect(config.sni, 'example.com');
      expect(config.fingerprint, 'chrome');
    });

    test('解析无端口链接 (默认 443)', () {
      const uri =
          'vless://uuid123@server.test:443?type=tcp&security=none#NoPort';

      final config = VlessConfig.fromUri(uri);

      expect(config.server, 'server.test');
      expect(config.port, 443);
    });

    test('解析无名称链接 (使用 server:port 作为名称)', () {
      const uri = 'vless://uuid123@server.test:8443?type=tcp&security=none';

      final config = VlessConfig.fromUri(uri);

      expect(config.name, 'server.test:8443');
    });

    test('解析 URL 编码的节点名称', () {
      const uri =
          'vless://uuid123@server.test:443?type=tcp&security=none#%E9%A6%99%E6%B8%AF%20%E8%8A%82%E7%82%B9';

      final config = VlessConfig.fromUri(uri);

      expect(config.name, '香港 节点');
    });

    test('无效 scheme 抛出异常', () {
      expect(
        () => VlessConfig.fromUri('http://example.com:443'),
        throwsA(isA<FormatException>()),
      );
    });

    test('缺少 UUID 抛出异常', () {
      expect(
        () => VlessConfig.fromUri('vless://example.com:443?type=tcp'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('VlessConfig 传输层解析', () {
    test('解析 VLESS+WebSocket', () {
      const uri =
          'vless://uuid@ws.server:443?type=ws&security=tls&path=%2Fws&sni=ws.server&host=ws.server&fp=chrome#WS-Node';

      final config = VlessConfig.fromUri(uri);

      expect(config.network, VlessNetwork.ws);
      expect(config.path, '/ws');
      expect(config.host, 'ws.server');
      expect(config.security, VlessSecurity.tls);
    });

    test('解析 VLESS+gRPC', () {
      const uri =
          'vless://uuid@grpc.server:443?type=grpc&security=tls&serviceName=myservice&mode=multi&sni=grpc.server#GRPC-Node';

      final config = VlessConfig.fromUri(uri);

      expect(config.network, VlessNetwork.grpc);
      expect(config.serviceName, 'myservice');
      expect(config.grpcMode, 'multi');
    });

    test('解析 VLESS+H2', () {
      const uri =
          'vless://uuid@h2.server:443?type=h2&security=tls&path=%2Fh2&host=h2.server&sni=h2.server#H2-Node';

      final config = VlessConfig.fromUri(uri);

      expect(config.network, VlessNetwork.h2);
      expect(config.path, '/h2');
      expect(config.host, 'h2.server');
    });

    test('默认传输层为 TCP', () {
      const uri = 'vless://uuid@server:443?security=none#TCP';

      final config = VlessConfig.fromUri(uri);

      expect(config.network, VlessNetwork.tcp);
    });
  });

  group('VlessConfig 安全层解析', () {
    test('解析 TLS 安全配置', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=tls&sni=my.server.com&fp=firefox&alpn=h2,http/1.1&allowInsecure=1#TLS';

      final config = VlessConfig.fromUri(uri);

      expect(config.security, VlessSecurity.tls);
      expect(config.sni, 'my.server.com');
      expect(config.fingerprint, 'firefox');
      expect(config.alpn, ['h2', 'http/1.1']);
      expect(config.allowInsecure, true);
    });

    test('解析 Reality 安全配置', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=abc123pubkey&sid=abcdef1234&flow=xtls-rprx-vision#Reality';

      final config = VlessConfig.fromUri(uri);

      expect(config.security, VlessSecurity.reality);
      expect(config.sni, 'www.microsoft.com');
      expect(config.publicKey, 'abc123pubkey');
      expect(config.shortId, 'abcdef1234');
      expect(config.flow, VlessFlow.xtlsRprxVision);
    });

    test('默认安全类型为 none', () {
      const uri = 'vless://uuid@server:443?type=tcp#NoSecurity';

      final config = VlessConfig.fromUri(uri);

      expect(config.security, VlessSecurity.none);
    });

    test('解析 allowInsecure=true 字符串', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=tls&allowInsecure=true#Insecure';

      final config = VlessConfig.fromUri(uri);

      expect(config.allowInsecure, true);
    });
  });

  group('VlessConfig 流控解析', () {
    test('解析 xtls-rprx-vision', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=key&sid=id&sni=sn#Vision';

      final config = VlessConfig.fromUri(uri);

      expect(config.flow, VlessFlow.xtlsRprxVision);
      expect(config.flow.toConfigValue(), 'xtls-rprx-vision');
    });

    test('解析 xtls-rprx-vision-udp443', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=reality&flow=xtls-rprx-vision-udp443&pbk=key&sid=id&sni=sn#VisionUDP';

      final config = VlessConfig.fromUri(uri);

      expect(config.flow, VlessFlow.xtlsRprxVisionUdp443);
      expect(config.flow.toConfigValue(), 'xtls-rprx-vision-udp443');
    });

    test('默认流控为 none', () {
      const uri = 'vless://uuid@server:443?type=tcp&security=none#NoFlow';

      final config = VlessConfig.fromUri(uri);

      expect(config.flow, VlessFlow.none);
      expect(config.flow.toConfigValue(), null);
    });
  });

  group('VlessConfig.toClashProxy Clash 配置生成', () {
    test('生成基础 TCP+None 配置', () {
      const uri =
          'vless://test-uuid@1.2.3.4:443?type=tcp&security=none#BasicNode';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['name'], 'BasicNode');
      expect(proxy['type'], 'vless');
      expect(proxy['server'], '1.2.3.4');
      expect(proxy['port'], 443);
      expect(proxy['uuid'], 'test-uuid');
      expect(proxy['udp'], true);
      expect(proxy['network'], 'tcp');
      expect(proxy['tls'], false);
    });

    test('生成 TLS 配置包含所有字段', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=tls&sni=my.server&fp=chrome&alpn=h2,http/1.1#TLS';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['tls'], true);
      expect(proxy['servername'], 'my.server');
      expect(proxy['client-fingerprint'], 'chrome');
      expect(proxy['alpn'], ['h2', 'http/1.1']);
    });

    test('生成 Reality 配置包含 reality-opts', () {
      const uri =
          'vless://uuid@server:443?type=tcp&security=reality&sni=www.test.com&fp=chrome&pbk=mypubkey&sid=shortid123&flow=xtls-rprx-vision#Reality';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['tls'], true);
      expect(proxy['servername'], 'www.test.com');
      expect(proxy['flow'], 'xtls-rprx-vision');

      final realityOpts = proxy['reality-opts'] as Map<String, dynamic>;
      expect(realityOpts['public-key'], 'mypubkey');
      expect(realityOpts['short-id'], 'shortid123');
    });

    test('生成 WebSocket 配置', () {
      const uri =
          'vless://uuid@server:443?type=ws&security=tls&path=%2Fwebsocket&host=custom.host.com&sni=server#WS';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['network'], 'ws');
      expect(proxy['tls'], true);

      final wsOpts = proxy['ws-opts'] as Map<String, dynamic>;
      expect(wsOpts['path'], '/websocket');
      expect((wsOpts['headers'] as Map)['Host'], 'custom.host.com');
    });

    test('生成 gRPC 配置', () {
      const uri =
          'vless://uuid@server:443?type=grpc&security=tls&serviceName=grpc-service&sni=server#GRPC';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['network'], 'grpc');
      expect(proxy['tls'], true);

      final grpcOpts = proxy['grpc-opts'] as Map<String, dynamic>;
      expect(grpcOpts['grpc-service-name'], 'grpc-service');
    });

    test('生成 H2 配置', () {
      const uri =
          'vless://uuid@server:443?type=h2&security=tls&path=%2Fh2path&host=h2.host.com&sni=server#H2';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['network'], 'h2');

      final h2Opts = proxy['h2-opts'] as Map<String, dynamic>;
      expect(h2Opts['path'], '/h2path');
      expect(h2Opts['host'], ['h2.host.com']);
    });

    test('skip-cert-verify 仅在 allowInsecure=true 时设置', () {
      const uriInsecure =
          'vless://uuid@server:443?type=tcp&security=tls&allowInsecure=1&sni=s#Insecure';
      const uriSecure =
          'vless://uuid@server:443?type=tcp&security=tls&sni=s#Secure';

      final insecureProxy = VlessConfig.fromUri(uriInsecure).toClashProxy();
      final secureProxy = VlessConfig.fromUri(uriSecure).toClashProxy();

      expect(insecureProxy['skip-cert-verify'], true);
      expect(secureProxy.containsKey('skip-cert-verify'), false);
    });

    test('http 传输层在 Clash 配置中 network 值为 h2', () {
      const uri =
          'vless://uuid@server:443?type=http&security=tls&path=%2Fpath&host=h.com&sni=s#HTTP';

      final config = VlessConfig.fromUri(uri);
      final proxy = config.toClashProxy();

      expect(proxy['network'], 'h2'); // http 映射为 h2
    });
  });

  group('VlessNetwork 枚举', () {
    test('fromString 正确解析', () {
      expect(VlessNetwork.fromString('tcp'), VlessNetwork.tcp);
      expect(VlessNetwork.fromString('ws'), VlessNetwork.ws);
      expect(VlessNetwork.fromString('grpc'), VlessNetwork.grpc);
      expect(VlessNetwork.fromString('h2'), VlessNetwork.h2);
      expect(VlessNetwork.fromString('http'), VlessNetwork.http);
    });

    test('clashValue 将 http 映射为 h2', () {
      expect(VlessNetwork.tcp.clashValue, 'tcp');
      expect(VlessNetwork.ws.clashValue, 'ws');
      expect(VlessNetwork.grpc.clashValue, 'grpc');
      expect(VlessNetwork.h2.clashValue, 'h2');
      expect(VlessNetwork.http.clashValue, 'h2'); // http 映射为 h2
    });

    test('fromString 未知值返回 tcp', () {
      expect(VlessNetwork.fromString('unknown'), VlessNetwork.tcp);
      expect(VlessNetwork.fromString(null), VlessNetwork.tcp);
    });
  });

  group('VlessSecurity 枚举', () {
    test('fromString 正确解析', () {
      expect(VlessSecurity.fromString('none'), VlessSecurity.none);
      expect(VlessSecurity.fromString('tls'), VlessSecurity.tls);
      expect(VlessSecurity.fromString('reality'), VlessSecurity.reality);
    });

    test('fromString 未知值返回 none', () {
      expect(VlessSecurity.fromString('xtls'), VlessSecurity.none);
      expect(VlessSecurity.fromString(null), VlessSecurity.none);
    });
  });

  group('VlessFlow 枚举', () {
    test('fromString 正确解析', () {
      expect(VlessFlow.fromString('xtls-rprx-vision'), VlessFlow.xtlsRprxVision);
      expect(
        VlessFlow.fromString('xtls-rprx-vision-udp443'),
        VlessFlow.xtlsRprxVisionUdp443,
      );
    });

    test('fromString 未知值返回 none', () {
      expect(VlessFlow.fromString('unknown'), VlessFlow.none);
      expect(VlessFlow.fromString(null), VlessFlow.none);
    });

    test('toConfigValue 正确转换', () {
      expect(VlessFlow.none.toConfigValue(), null);
      expect(VlessFlow.xtlsRprxVision.toConfigValue(), 'xtls-rprx-vision');
      expect(
        VlessFlow.xtlsRprxVisionUdp443.toConfigValue(),
        'xtls-rprx-vision-udp443',
      );
    });
  });
}
