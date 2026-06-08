// VLESS 协议链接解析器
// 支持 vless:// URI scheme 解析，并转换为 mihomo (ClashMeta) 兼容的 YAML 代理配置
//
// URI 格式: vless://uuid@server:port?params#name
// 参数文档: https://github.com/XTLS/Xray-core/issues/91

import 'dart:convert';
import 'package:fl_clash/common/common.dart';

/// 传输层类型
enum VlessNetwork {
  tcp,
  ws,
  grpc,
  h2,
  http;

  static VlessNetwork fromString(String? value) {
    return VlessNetwork.values.firstWhere(
      (e) => e.name == value,
      orElse: () => VlessNetwork.tcp,
    );
  }

  /// mihomo 配置中的 network 值 (http 映射为 h2)
  String get clashValue => switch (this) {
    VlessNetwork.http => 'h2',
    _ => name,
  };
}

/// TLS 安全类型
enum VlessSecurity {
  none,
  tls,
  reality;

  static VlessSecurity fromString(String? value) {
    return VlessSecurity.values.firstWhere(
      (e) => e.name == value,
      orElse: () => VlessSecurity.none,
    );
  }
}

/// XTLS 流控模式
enum VlessFlow {
  none,
  xtlsRprxVision,
  xtlsRprxVisionUdp443;

  static VlessFlow fromString(String? value) {
    switch (value) {
      case 'xtls-rprx-vision':
        return VlessFlow.xtlsRprxVision;
      case 'xtls-rprx-vision-udp443':
        return VlessFlow.xtlsRprxVisionUdp443;
      default:
        return VlessFlow.none;
    }
  }

  String? toConfigValue() {
    switch (this) {
      case VlessFlow.none:
        return null;
      case VlessFlow.xtlsRprxVision:
        return 'xtls-rprx-vision';
      case VlessFlow.xtlsRprxVisionUdp443:
        return 'xtls-rprx-vision-udp443';
    }
  }
}

/// VLESS 配置模型
class VlessConfig {
  /// UUID
  final String uuid;

  /// 服务器地址
  final String server;

  /// 端口
  final int port;

  /// 节点名称 (来自 fragment #name)
  final String name;

  /// 传输协议类型
  final VlessNetwork network;

  /// 安全层类型
  final VlessSecurity security;

  /// TLS SNI
  final String? sni;

  /// TLS Peer (Reality 场景下的 SNI)
  final String? peer;

  /// TLS 指纹
  final String? fingerprint;

  /// ALPN 列表
  final List<String>? alpn;

  /// 是否允许不安全证书
  final bool allowInsecure;

  /// XTLS 流控
  final VlessFlow flow;

  /// WebSocket / H2 路径
  final String? path;

  /// WebSocket / H2 Host
  final String? host;

  /// gRPC 服务名
  final String? serviceName;

  /// gRPC 多路复用模式
  final String? grpcMode;

  /// Reality 公钥
  final String? publicKey;

  /// Reality Short ID
  final String? shortId;

  /// Reality Server Name
  final String? serverName;

  VlessConfig({
    required this.uuid,
    required this.server,
    required this.port,
    this.name = '',
    this.network = VlessNetwork.tcp,
    this.security = VlessSecurity.none,
    this.sni,
    this.peer,
    this.fingerprint,
    this.alpn,
    this.allowInsecure = false,
    this.flow = VlessFlow.none,
    this.path,
    this.host,
    this.serviceName,
    this.grpcMode,
    this.publicKey,
    this.shortId,
    this.serverName,
  });

  /// 从 vless:// 链接解析
  factory VlessConfig.fromUri(String uriString) {
    // 处理 base64 编码的 vless 链接
    final content = _tryDecodeBase64(uriString);

    final uri = Uri.parse(content);

    if (uri.scheme != 'vless') {
      throw FormatException('不是有效的 VLESS 链接: scheme="${uri.scheme}"');
    }

    final uuid = uri.userInfo;
    if (uuid.isEmpty) {
      throw const FormatException('VLESS 链接缺少 UUID');
    }

    // 服务器地址: 处理 IPv6
    final server = _extractServer(uri);
    if (server.isEmpty) {
      throw const FormatException('VLESS 链接缺少服务器地址');
    }

    final port = uri.hasPort ? uri.port : 443;

    // 节点名称 (URL 解码 fragment)
    final name = uri.fragment.isNotEmpty
        ? Uri.decodeComponent(uri.fragment)
        : '$server:$port';

    final params = uri.queryParameters;

    // 解析 ALPN (逗号分隔)
    final alpnStr = params['alpn'];
    final alpn =
        alpnStr != null && alpnStr.isNotEmpty
            ? alpnStr.split(',').where((s) => s.isNotEmpty).toList()
            : null;

    return VlessConfig(
      uuid: uuid,
      server: server,
      port: port,
      name: name,
      network: VlessNetwork.fromString(params['type']),
      security: VlessSecurity.fromString(params['security']),
      sni: params['sni'],
      peer: params['peer'],
      fingerprint: params['fp'],
      alpn: alpn,
      allowInsecure: params['allowInsecure'] == '1' ||
          params['allowInsecure'] == 'true',
      flow: VlessFlow.fromString(params['flow']),
      path: params['path'],
      host: params['host'],
      serviceName: params['serviceName'],
      grpcMode: params['mode'],
      publicKey: params['pbk'],
      shortId: params['sid'],
      serverName: params['sni'] ?? params['peer'],
    );
  }

  /// 尝试 base64 解码 (兼容 `vless://<base64>` 格式)
  static String _tryDecodeBase64(String uriString) {
    const prefix = 'vless://';
    if (!uriString.startsWith(prefix)) return uriString;

    final body = uriString.substring(prefix.length);

    // 如果 body 不含 @ 和 : 则可能是 base64 编码
    if (!body.contains('@') && !body.contains(':')) {
      try {
        final normalized = base64.normalize(body);
        final decoded = utf8.decode(base64.decode(normalized));
        return 'vless://$decoded';
      } catch (_) {
        // 解码失败，返回原始字符串
      }
    }

    return uriString;
  }

  /// 提取服务器地址 (处理 IPv6)
  static String _extractServer(Uri uri) {
    return uri.host;
  }

  /// 转换为 mihomo (ClashMeta) 代理配置 Map
  Map<String, dynamic> toClashProxy() {
    final proxy = <String, dynamic>{
      'name': name,
      'type': 'vless',
      'server': server,
      'port': port,
      'uuid': uuid,
      'udp': true,
      'network': network.clashValue,
    };

    // 流控
    final flowValue = flow.toConfigValue();
    if (flowValue != null) {
      proxy['client-fingerprint'] = fingerprint ?? 'chrome';
      proxy['flow'] = flowValue;
    }

    // TLS / Reality 配置
    _applyTlsConfig(proxy);

    // 传输层配置
    _applyNetworkConfig(proxy);

    return proxy;
  }

  /// 应用 TLS/Reality 配置
  void _applyTlsConfig(Map<String, dynamic> proxy) {
    switch (security) {
      case VlessSecurity.tls:
        proxy['tls'] = true;
        if (sni != null && sni!.isNotEmpty) {
          proxy['servername'] = sni;
        }
        if (fingerprint != null && fingerprint!.isNotEmpty) {
          proxy['client-fingerprint'] = fingerprint;
        }
        if (alpn != null && alpn!.isNotEmpty) {
          proxy['alpn'] = alpn;
        }
        if (allowInsecure) {
          proxy['skip-cert-verify'] = true;
        }
        break;

      case VlessSecurity.reality:
        proxy['tls'] = true;
        if (sni != null && sni!.isNotEmpty) {
          proxy['servername'] = sni;
        }
        if (fingerprint != null && fingerprint!.isNotEmpty) {
          proxy['client-fingerprint'] = fingerprint;
        }
        if (alpn != null && alpn!.isNotEmpty) {
          proxy['alpn'] = alpn;
        }
        // Reality 专用选项
        final realityOpts = <String, dynamic>{};
        if (publicKey != null && publicKey!.isNotEmpty) {
          realityOpts['public-key'] = publicKey;
        }
        if (shortId != null && shortId!.isNotEmpty) {
          realityOpts['short-id'] = shortId;
        }
        if (serverName != null && serverName!.isNotEmpty) {
          realityOpts['server-name'] = serverName;
        }
        if (realityOpts.isNotEmpty) {
          proxy['reality-opts'] = realityOpts;
        }
        break;

      case VlessSecurity.none:
        proxy['tls'] = false;
        break;
    }
  }

  /// 应用传输层配置
  void _applyNetworkConfig(Map<String, dynamic> proxy) {
    switch (network) {
      case VlessNetwork.ws:
        final wsOpts = <String, dynamic>{};
        if (path != null && path!.isNotEmpty) {
          wsOpts['path'] = path;
        }
        if (host != null && host!.isNotEmpty) {
          wsOpts['headers'] = {'Host': host};
        }
        if (wsOpts.isNotEmpty) {
          proxy['ws-opts'] = wsOpts;
        }
        break;

      case VlessNetwork.grpc:
        final grpcOpts = <String, dynamic>{};
        if (serviceName != null && serviceName!.isNotEmpty) {
          grpcOpts['grpc-service-name'] = serviceName;
        }
        if (grpcOpts.isNotEmpty) {
          proxy['grpc-opts'] = grpcOpts;
        }
        break;

      case VlessNetwork.h2:
      case VlessNetwork.http:
        final h2Opts = <String, dynamic>{};
        if (path != null && path!.isNotEmpty) {
          h2Opts['path'] = path;
        }
        if (host != null && host!.isNotEmpty) {
          h2Opts['host'] = [host];
        }
        if (h2Opts.isNotEmpty) {
          proxy['h2-opts'] = h2Opts;
        }
        break;

      case VlessNetwork.tcp:
        break;
    }
  }

  /// 生成 Clash YAML 配置字符串 (仅代理节点)
  String toClashYaml() {
    final config = {
      'proxies': [toClashProxy()],
    };
    return yaml.encode(config);
  }

  /// 生成完整的 Clash 配置文件 (含基础设置、代理组、规则)
  String toFullClashYaml() {
    final config = {
      'mixed-port': 7890,
      'allow-lan': false,
      'mode': 'rule',
      'log-level': 'info',
      'proxies': [toClashProxy()],
      'proxy-groups': [
        {
          'name': 'PROXY',
          'type': 'select',
          'proxies': [name],
        },
      ],
      'rules': ['MATCH,PROXY'],
    };
    return yaml.encode(config);
  }
}
