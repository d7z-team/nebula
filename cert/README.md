# 节点证书与信任池

每个节点持有自己的主机证书、与证书匹配的密钥协商私钥，以及用于验证本机和对端证书的 CA 池。`nebula.Identity.PrivateKey` 接受解码后的原始私钥字节。CA 签名私钥由签发端保管。

## 加载已有 PEM

下面的函数接受一个主机证书 PEM、对应的主机私钥 PEM 和一个可含多个 CA 的 PEM 文件内容。返回值可直接传给[挂载示例](../docs/quickstart.md)。

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

签发端用 `cert.CreateCA` 建立 CA。对于本指南的网关示例，CA 的 `Networks` 可限定为 `10.42.0.0/24`，`UnsafeNetworks` 可限定为 `192.168.50.0/24`。以下片段使用 CA 证书 `ca` 和原始签名私钥 `signingKey` 返回网关身份。

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

签发客户端时，将 `Name` 设为 `client`，`Networks` 设为 `10.42.0.1/24`，`UnsafeNetworks` 留空。主机前缀保留主机位，后面的 `/24` 描述它所在的 overlay 网段。网关证书赋予承载下游流量的权限，实际路由和转发在宿主 gVisor 栈配置。[网关配置](../docs/nebula-nic.md#经网关访问下游子网)

如需由节点自行保管私钥，在节点上用 `cert.GenerateKeyAgreementKey` 生成密钥对，仅将公钥交给签发端填入 `CertificateOptions.PublicKey`。这种用法下，`IssueCertificate` 的私钥返回值为 nil。保存证书使用 `host.MarshalPEM()`，保存主机私钥使用 `cert.MarshalPrivateKeyToPEM`。

## 格式与互通

v2 证书支持 IPv4 和 IPv6，v1 证书使用 IPv4。一个节点可各配置一份 v1 和 v2 身份，两者须使用相同的密钥、曲线、overlay 前缀和 unsafe 前缀。FIPS 140-only 部署使用 P256 和 AES。[v2 ASN.1 定义](cert_v2.asn1) · [v1 Protobuf 定义](cert_v1.proto)

修改 v1 的 protobuf 定义后，在装有 `protoc` 的环境从仓库根目录运行 `make -C cert proto` 重新生成 Go 绑定。
