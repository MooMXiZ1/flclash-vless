// 协议解析管理器单元测试
//
// 运行方式: flutter test test/protocol_parser_test.dart

import 'package:fl_clash/common/protocol_parser.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ProxyProtocolParser.isProtocolLink', () {
    test('识别 vless:// 链接', () {
      expect(
        proxyProtocolParser.isProtocolLink('vless://uuid@server:443'),
        true,
      );
    });

    test('不识别 HTTP URL', () {
      expect(
        proxyProtocolParser.isProtocolLink('https://example.com/sub'),
        false,
      );
    });

    test('不识别无关字符串', () {
      expect(proxyProtocolParser.isProtocolLink('hello world'), false);
      expect(proxyProtocolParser.isProtocolLink(''), false);
    });

    test('处理前后空白', () {
      expect(
        proxyProtocolParser.isProtocolLink('  vless://uuid@server  '),
        true,
      );
    });
  });

  group('ProxyProtocolParser.parse', () {
    test('成功解析 VLESS 链接', () {
      const uri =
          'vless://test-uuid@1.2.3.4:443?type=tcp&security=none#TestNode';

      final result = proxyProtocolParser.parse(uri);

      expect(result, isNotNull);
      expect(result!.protocol, 'vless');
      expect(result.name, 'TestNode');
      expect(result.yamlContent, isNotEmpty);
    });

    test('无效链接返回 null', () {
      final result = proxyProtocolParser.parse('invalid://link');
      expect(result, isNull);
    });

    test('非协议链接返回 null', () {
      final result = proxyProtocolParser.parse('https://example.com');
      expect(result, isNull);
    });
  });

  group('ProxyProtocolParser.parseMultiple', () {
    test('解析多个 VLESS 链接', () {
      const input = '''
vless://uuid1@server1:443?type=tcp&security=none#Node1
vless://uuid2@server2:443?type=ws&security=tls&path=%2Fws&sni=server2&host=server2#Node2
''';

      final result = proxyProtocolParser.parseMultiple(input);

      expect(result, isNotNull);
      expect(result!.protocol, 'mixed');
      expect(result.name, '2 个节点');
      expect(result.yamlContent, contains('Node1'));
      expect(result.yamlContent, contains('Node2'));
    });

    test('单个链接走 parse 逻辑', () {
      const input =
          'vless://uuid@server:443?type=tcp&security=none#SingleNode';

      final result = proxyProtocolParser.parseMultiple(input);

      expect(result, isNotNull);
      expect(result!.protocol, 'vless');
    });

    test('全部无效链接返回 null', () {
      const input = '''
invalid://link1
http://not-a-protocol
random text
''';

      final result = proxyProtocolParser.parseMultiple(input);
      expect(result, isNull);
    });

    test('跳过无效链接，解析有效链接', () {
      const input = '''
vless://uuid@valid-server:443?type=tcp&security=none#ValidNode
invalid://bad-link
''';

      final result = proxyProtocolParser.parseMultiple(input);

      expect(result, isNotNull);
      expect(result!.yamlContent, contains('ValidNode'));
    });
  });

  group('ProtocolLinkExtension', () {
    test('String.isProtocolLink 扩展方法', () {
      expect('vless://uuid@server:443'.isProtocolLink, true);
      expect('https://example.com'.isProtocolLink, false);
      expect(''.isProtocolLink, false);
    });
  });
}
