# 节点证书与信任池

每个节点持有自己的主机证书、与证书匹配的密钥协商私钥，以及用于验证本机和对端证书的 CA 池。`nebula.Identity.PrivateKey` 接受解码后的原始私钥字节。CA 签名私钥由签发端保管。

## 加载已有 PEM

将主机证书、对应私钥和 CA 证书包的 PEM 文件内容传给 `LoadIdentity`，再用返回的身份和信任池创建节点。CA 证书包可以包含多个 CA。[挂载示例](../docs/quickstart.md)

```go
package client

import (
	"fmt"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
)

func LoadIdentity(hostPEM, keyPEM, caPEM []byte) (nebula.Identity, *cert.CAPool, error) {
	host, _, err := cert.UnmarshalCertificateFromPEM(hostPEM)
	if err != nil {
		return nebula.Identity{}, nil, fmt.Errorf("host certificate: %w", err)
	}
	key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nebula.Identity{}, nil, fmt.Errorf("host key: %w", err)
	}
	if curve != host.Curve() {
		return nebula.Identity{}, nil, fmt.Errorf("key curve %v differs from certificate curve %v", curve, host.Curve())
	}
	pool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		return nebula.Identity{}, nil, fmt.Errorf("CA pool: %w", err)
	}
	return nebula.Identity{Certificate: host, PrivateKey: key}, pool, nil
}
```

`nebula.New` 会检查主机证书有效期、CA 签名以及公私钥是否匹配。已有解析好的 CA 证书也可通过 `cert.NewCAPool()` 和 `pool.AddCA(ca)` 加入信任池。

## 签发客户端与网关证书

签发端用 `cert.CreateCA` 创建 CA，默认签发 v2 CA 证书。`cert.IssueCertificate` 默认沿用 CA 的证书版本。对于本指南的网关示例，CA 的 `Networks` 可限定为 `10.42.0.0/24`，`UnsafeNetworks` 可限定为 `192.168.50.0/24`。以下片段使用 CA 证书 `ca` 和原始签名私钥 `signingKey` 返回网关身份。

```go
host, key, err := cert.IssueCertificate(ca, signingKey, cert.CertificateOptions{
	Name:           "gateway",
	Networks:       []netip.Prefix{netip.MustParsePrefix("10.42.0.254/24")},
	UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")},
})
if err != nil {
	return nebula.Identity{}, err
}
return nebula.Identity{Certificate: host, PrivateKey: key}, nil
```

签发客户端时，将 `Name` 设为 `client`，在 `Networks` 中填写 `10.42.0.1/24`，`UnsafeNetworks` 留空。前缀中的 `10.42.0.1` 是节点身份，`/24` 指定 overlay 网段。签发网关证书后，在客户端添加下游路由，在网关的 gVisor 栈上启用转发。[网关配置](../docs/nebula-nic.md#经网关访问下游子网)

如需由节点自行保管私钥，在节点上用 `cert.GenerateKeyAgreementKey` 生成密钥对，仅将公钥交给签发端填入 `CertificateOptions.PublicKey`。这种用法下，`IssueCertificate` 的私钥返回值为 nil。保存证书使用 `host.MarshalPEM()`，保存主机私钥使用 `cert.MarshalPrivateKeyToPEM`。

## 受管网络的信任配置

| 凭证 | 配置位置 | 用途 |
| --- | --- | --- |
| 主机身份及其受信 CA | `Options.Identities`、`Options.CAPool` | Nebula 握手验证对端身份，收发 IP 包时检查证书授权的地址和子网。 |
| 配置 CA 公共证书 | `ControlOptions.Authority` | 节点以部署时指定的 CA 验证完整网络配置。签发机持有对应私钥，可用 `cert.MarshalSigningPrivateKeyToPEM` 保存供 `nebula-config` 使用。 |
| 成员 Ed25519 发布密钥 | 本机 `ControlOptions.Publisher` 私钥、签名成员记录中的 `publisher` 公钥 | 签名端点介绍和获准主题的应用事件。 |

普通节点只需主机身份和信任池。受管节点可以使用独立的配置 CA。要吊销主机证书，用 `host.Fingerprint()` 取得小写十六进制指纹，纳入下一版完整的 `revoked` 列表。变更在各节点安装该版本时生效。成员记录固定的 `certificate` 指纹命中列表时，该成员的事件发布权限也会停用。使用独立发布密钥且未设置 `certificate` 的成员，可以在同一版本清空 `publisher` 和 `topics` 来撤回发布权限。[签发与分发网络配置](../docs/control.md#签发配置)

## 格式与互通

v2 证书支持 IPv4 和 IPv6，v1 证书使用 IPv4。一个节点可各配置一份 v1 和 v2 身份，两者须使用相同的密钥和曲线，`Networks` 和 `UnsafeNetworks` 的内容及顺序也要一致。FIPS 140-only 部署使用 P256 和 AES。[v2 ASN.1 定义](cert_v2.asn1) · [v1 Protobuf 定义](cert_v1.proto)

修改 v1 的 protobuf 定义后，在装有 `protoc` 的环境从仓库根目录运行 `make -C cert proto` 重新生成 Go 绑定。
