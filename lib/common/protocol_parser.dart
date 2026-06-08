// 代理协议链接解析管理器
// 统一入口，支持检测并解析各种代理协议链接，转换为 Clash YAML 配置
//
// 目前支持的协议:
//   - vless:// (VLESS)
//
// 后续可扩展:
//   - vmess:// (VMess)
//   - trojan:// (Trojan)
//   - ss:// (Shadowsocks)
//   - ssr:// (ShadowsocksR)

import 'package:fl_clash/common/common.dart';
import 'protocol/vless.dart';

/// 协议解析结果
class ProtocolParseResult {
  /// 协议类型名称
  final String protocol;

  /// 解析后的节点名称
  final String name;

  /// 生成的 Clash YAML 配置
  final String yamlContent;

  ProtocolParseResult({
    required this.protocol,
    required this.name,
    required this.yamlContent,
  });
}

/// 代理协议解析器
class ProxyProtocolParser {
  static ProxyProtocolParser? _instance;
  ProxyProtocolParser._internal();

  factory ProxyProtocolParser() {
    _instance ??= ProxyProtocolParser._internal();
    return _instance!;
  }

  /// 协议 scheme → 单链接解析函数 的映射表
  /// 扩展新协议时只需在此处添加条目，并在下方实现对应的 _parseXxx 方法
  static final Map<String, ProtocolParseResult? Function(String)> _parsers = {
    'vless': _parseVless,
    // 后续扩展:
    // 'vmess': _parseVmess,
    // 'trojan': _parseTrojan,
    // 'ss': _parseSs,
  };

  /// 所有支持的协议 scheme 列表 (由 _parsers 自动派生)
  List<String> get supportedSchemes => _parsers.keys.toList();

  /// 检测字符串是否为支持的协议链接
  bool isProtocolLink(String input) {
    final trimmed = input.trim();
    return _parsers.keys.any((scheme) => trimmed.startsWith('$scheme://'));
  }

  /// 解析协议链接，返回 Clash YAML 配置
  ///
  /// [input] 为单个协议链接
  /// 返回 null 表示解析失败
  ProtocolParseResult? parse(String input) {
    final trimmed = input.trim();

    // 通过映射表 dispatch 到对应的解析器
    for (final entry in _parsers.entries) {
      if (trimmed.startsWith('${entry.key}://')) {
        return entry.value(trimmed);
      }
    }

    return null;
  }

  /// 解析多个协议链接 (换行分隔)，生成合并的 Clash 配置
  ProtocolParseResult? parseMultiple(String input) {
    final lines = input
        .split(RegExp(r'[\r\n]+'))
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty)
        .toList();

    if (lines.length == 1) {
      return parse(lines.first);
    }

    // 多链接模式：收集所有代理节点
    final proxies = <Map<String, dynamic>>[];
    final names = <String>[];

    for (final line in lines) {
      try {
        // 尝试所有已注册的协议解析器
        for (final entry in _parsers.entries) {
          if (line.startsWith('${entry.key}://')) {
            final config = VlessConfig.fromUri(line);
            proxies.add(config.toClashProxy());
            names.add(config.name);
            break;
          }
        }
      } catch (e) {
        // 日志中脱敏处理：只记录前 20 个字符，避免泄露 UUID 等敏感信息
        final masked =
            line.length > 20 ? '${line.substring(0, 20)}...' : line;
        commonPrint.log('解析协议链接失败: $masked, 错误: $e');
      }
    }

    if (proxies.isEmpty) return null;

    final config = {
      'mixed-port': 7890,
      'allow-lan': false,
      'mode': 'rule',
      'log-level': 'info',
      'proxies': proxies,
      'proxy-groups': [
        {
          'name': 'PROXY',
          'type': 'select',
          'proxies': names,
        },
      ],
      'rules': ['MATCH,PROXY'],
    };

    return ProtocolParseResult(
      protocol: 'mixed',
      name: '${proxies.length} 个节点',
      yamlContent: yaml.encode(config),
    );
  }

  /// 解析 VLESS 链接
  static ProtocolParseResult? _parseVless(String input) {
    try {
      final config = VlessConfig.fromUri(input);
      return ProtocolParseResult(
        protocol: 'vless',
        name: config.name,
        yamlContent: config.toFullClashYaml(),
      );
    } catch (e) {
      commonPrint.log('VLESS 链接解析失败: $e');
      return null;
    }
  }
}

final proxyProtocolParser = ProxyProtocolParser();

/// String 扩展：检测是否为协议链接
extension ProtocolLinkExtension on String {
  bool get isProtocolLink => proxyProtocolParser.isProtocolLink(this);
}
