# Go PKI 接口

企业 CA 和项目自带的 `nebula-pki` 均可签发符合下述配置的 X.509 v3 证书。Go 应用也可直接调用 `pki` 包，在进程内生成密钥、签发和验证证书。私钥文件使用 PKCS#8 PEM，外部签名器实现 `crypto.Signer`；CSR 使用 PKCS#10，证书使用 DER 或 PEM。[接入示例](quickstart.md) · [X.509](https://www.rfc-editor.org/rfc/rfc5280) · [PKCS#10](https://www.rfc-editor.org/rfc/rfc2986)

| 操作 | API | 调用方提供的材料 |
| --- | --- | --- |
| 生成密钥 | `pki.GenerateKey` 或 Go 标准库 | 内置便捷生成器支持 ed25519、p256、3072 位 RSA 和 ml-dsa-44。TLS 可用签名算法由 Go 和对端协商。 |
| 根与中间 CA | `CreateRoot`、`Issuer.IssueCA` | 根使用自己的签名器。签发中间 CA 时提供 CSR、获批签发配置和独立批准的 SPKI SHA-256。签发库验证 CSR 签名、公钥指纹及上级约束。 |
| 申请与签发叶证书 | `CreateCSR`、`Issuer.IssueLeaf` | 申请者提交自签名 CSR。签发者以独立批准的 SPKI SHA-256、一个 IPv4 和一个 IPv6 SAN、网络、下游路由前缀、用途和有效期构造证书。签发端逐一用给定签发链验证所申请的 EKU，可在签发时发现上级 CA 对用途的限制。CA 和叶密钥可以使用不同算法。 |
| 装载与验证 | `tls.LoadX509KeyPair`、`ParseCertificatesPEM`、`ParseChain`、`VerifyChain` | PEM 文件可包含多张证书；TLS 的 DER 链每个元素恰为一张证书，叶在前。验证时给出可信根、固定的集群 CA 规划、完整地址对、用途和时刻。 |
| 签名对象 | `CheckObjectSize`、`SignObject`、`VerifyObjectSignature` | 预检和签名使用相同的网络名、用途、正文和证书链。独立验签后还需验证证书链与业务授权。[签名对象](#签名对象) |

## 进程内签发与验证

运行 `go run ./examples/pki`，示例将 `10.13.0.0/27` 和 `fd13::/120` 委派给站点 CA，签发成员证书并验证其服务端用途。预期输出为 `verified 10.13.0.1@fd13::1 on demo for serverAuth`。[完整示例](../examples/pki/main.go)

签发中间 CA 时调用 `issuer.IssueCA(csr, profile, approvedKeyHash)`。第三个参数是经独立渠道批准的公钥 SubjectPublicKeyInfo DER 的 SHA-256，类型为 `[32]byte`。叶证书在 `Enrollment.PublicKeyHash` 传入同类指纹。两种签发均由库核对请求签名和指纹；CLI 从十六进制的 `-approved-key` 读取该参数。根 CA 要签发一级中间 CA 时设 `MaxPathLen: 1` 或 `-path-len 1`。`0` 表示该 CA 可直接签发叶证书。[签发实现](../pki/issuance.go)

## 签发证书

在仓库根目录的 POSIX shell 执行以下命令，创建临时目录和测试 CA。每个节点各生成一把私钥，证书中同时写入它的虚拟 IPv4、IPv6 和网络名。示例在同一台机器上从已知节点密钥提取公钥指纹。分机部署时，申请方保管私钥，签发者通过独立可信的渠道取得获批公钥指纹，再核对提交的 CSR。

```sh
lab=$(mktemp -d)
go build -o "$lab/nebula-pki" ./cmd/nebula-pki
(
  set -eu
  cd "$lab"
  ./nebula-pki keygen -algorithm p256 -out ca.key
  ./nebula-pki root -key ca.key -name "Demo CA" -cluster -network demo -permit-ips 10.13.0.0/24,fd13::/64 -days 30 -out ca.pem
  n=0
  for name in alice bob; do
    n=$((n + 1))
    ./nebula-pki keygen -out "$name.key"
    ./nebula-pki request -key "$name.key" -name "$name" -out "$name.csr"
    hash=$(./nebula-pki inspect -in "$name.key" -fingerprint)
    ./nebula-pki issue -ca ca.pem -ca-key ca.key -in "$name.csr" \
      -approved-key "$hash" -network demo -ipv4 "10.13.0.$n" -ipv6 "fd13::$n" -name "$name" -days 7 -out "$name.pem"
    ./nebula-pki verify -in "$name.pem" -cluster-ca ca.pem -ipv4 "10.13.0.$n" -ipv6 "fd13::$n" -roots ca.pem
  done
)
```

生成的 `alice.pem` 和 `alice.key` 可通过 `tls.LoadX509KeyPair` 装载。本例直接由根签发；使用中间 CA 时，将签发输出按叶证书在先的顺序与中间 CA 拼成一个 PEM 链文件，可信根单独交付。`nebula-pki -h` 列出命令，`nebula-pki issue -h` 列出签发参数。两端可使用这组材料启动独立进程并核对应用回执。[双进程接入](quickstart.md#使用磁盘凭据启动两个进程)

## 证书配置

成员叶证书必须有两个 `iPAddress` SAN，分别用 4 字节编码 IPv4、16 字节编码原生 IPv6。证书中两项的顺序任意。mesh 扩展的 OID 为 `1.2.840.113556.1.8000.2554.26659.52563.57837.16539.38613.9490006.11144251`，关键性标志为 false。其 DER 值为以下 ASN.1 结构。

```asn1
MeshScope ::= SEQUENCE {
    network UTF8String,
    routedPrefixes SEQUENCE OF Prefix,
    cluster BOOLEAN,
    anycastPools SEQUENCE OF Prefix,
    anycastIPs SEQUENCE OF OCTET STRING
}
Prefix ::= SEQUENCE { address OCTET STRING, bits INTEGER }
```

网络名使用 1 至 128 个小写 ASCII 字母、数字、下划线、点或连字符。前缀地址按网络序编码，主机位置零。字段顺序固定，空列表编码为空序列。

| 证书 | 签发配置 | `nebula-pki inspect` |
| --- | --- | --- |
| 集群 CA | `-cluster -network demo -permit-ips IPv4网段,IPv6网段` 固定两个成员网段。可用 `-routes` 和 `-anycast-pools` 分别委派下游路由和服务池。企业根下签发时，两个网段都须符合签发链的 IP 约束。 | `memberIPv4`、`memberIPv6` |
| 站点 CA | `issue -role ca -permit-ips IPv4范围,IPv6范围` 指定双栈签发范围，同族可列多段。每段须在上级许可内，并避开上级排除范围。仅签发普通成员时，指定 `-network` 并留空路由和服务池。 | `permittedIPs` |
| 成员 | 两个主地址写入 SAN。用 `-routes` 授权下游前缀，用 `-anycast-ips` 授权精确服务地址。 | `peer`、`routes`、`anycastIPs` |

企业 CA 可通过 X.509 名称约束的 `excludedSubtrees` 排除 IP 范围，成员地址校验和枚举均遵守这些约束。使用自带签发工具时，可在宿主分配台账中预留业务地址。签发端先校验集群地址规划，再调用 `crypto.Signer`。成员分配与站点委派的示例见[集群地址与 IP 交付](addressing.md)。

签发节点证书时，`nebula-pki issue` 使用 `-network`、`-ipv4`、`-ipv6` 和经独立批准的 `-approved-key`。默认 `-role node` 同时包含 clientAuth、serverAuth、codeSigning。使用独立凭据时，分别以 `-role client`、`-role server`、`-role object` 签发同一地址对的三张证书，填入 `LocalCertificates.Client`、`Server`、`Object`。PEM 链从叶证书开始，随后依次放入中间 CA。验证单一用途时，给 `nebula-pki verify` 传入相应的 `-role`。[签发与验证示例](#签发证书)

通过 API 读取证书时，`pki.ReadIdentity(cert)` 提取声明，`pki.VerifyChain(chain, roots, cluster, peer, usage, now)` 验证其信任路径。签发有效期按 DER 的整秒精度检查。PKIX 验证包含到期时刻，节点的会话和缓存授权在到达截止时刻时失效。[证书边界测试](../pki/boundaries_test.go)

## 热加载与宿主授权

同一成员换证时装入完整的新凭据。以下片段适用于客户端、服务端和对象签名共用一张具有三项 EKU 的证书。使用分角色证书时同时填入 `Server` 和 `Object`。

```go
pair, err := tls.LoadX509KeyPair(chainFile, keyFile)
if err != nil {
    return err
}
return node.ReloadCertificates(ctx, nebula.LocalCertificates{Client: pair})
```

成功后，新握手读取新凭据，已建立路径可通过 `node.Paths()` 核对握手实际使用的 `LocalSerial` 和对端 `Serial`。信任根在 `New` 时克隆。变更根池时，用新根构建节点。[凭据生命周期](mesh.md#证书生命周期与宿主授权)

`Options.Auth.CheckChain` 接收通过 PKIX 验证的候选链。宿主可以按证书的 SHA-256 指纹维护自己的授权数据，例如在 `New` 前设置以下钩子。这里的 `denied` 是该宿主实例持有的并发映射。

```go
var denied sync.Map
opts.Auth.CheckChain = func(ctx context.Context, check nebula.ChainCheck) (time.Time, error) {
    for _, cert := range check.Chain {
        if _, found := denied.Load(sha256.Sum256(cert.Raw)); found {
            return time.Time{}, errors.New("certificate denied by host")
        }
    }
    return time.Time{}, ctx.Err()
}
```

监控本机授权有效期时读取 `node.ControlStatus().AuthorizedUntil`，它取客户端、服务端和对象签名三个用途的最早授权截止时间，并包含宿主钩子给出的期限。

撤回信任时，先更新钩子读取的授权数据，再调用 `Revalidate` 复查现有授权。[复查范围](integration.md#选择本机安全策略)

```go
denied.Store(sha256.Sum256(withdrawn.Raw), struct{}{})
return node.Revalidate(ctx)
```

## 签名对象

节点用 CMS（Cryptographic Message Syntax）的 SignedData 封装签名主题消息和成员介绍。独立验签时，向 `VerifyObjectSignature` 传入预期网络和用途：主题消息使用 `publication`，成员介绍使用 `introduction`。核对签名后，用可信根、集群 CA、预期发布者身份及 `codeSigning` 调用 `VerifyChain`，再检查正文中的成员绑定和业务权限。`Node.Subscribe` 交付的消息已经过节点校验。运行 `go test -v -run '^ExampleVerifyObjectSignature$' ./pki` 可验证独立验签流程。[签名正文格式](mesh.md#控制消息的-json-格式) · [独立验签示例](../pki/example_test.go)

CMS 使用 DER 编码的封装型 SignedData，包含一个 SignerInfo、叶证书和所提供的中间证书。签名属性包含 content-type 与 message-digest。签名正文将网络、用途、叶证书的 SHA-256 和业务内容绑定在一起；发布者的网络成员 ID 位于业务内容中。实现覆盖 Ed25519、ECDSA、RSA 和 ML-DSA。签名证书与签发 CA 可以采用不同的算法。主题消息接收方逐次验证原发布者，转发者的连接身份只说明直接来源。[CMS 格式](https://www.rfc-editor.org/rfc/rfc5652) · [签名与解析](../pki/cms.go) · [签发与互操作测试](../pki/pki_test.go)

独立签名前，用 `pki.CheckObjectSize(network, kind, body, cert)` 检查完整 CMS DER 是否能放进 44 KiB。传入证书链即可，预检按该公钥的最大签名长度计算。用 `errors.Is(err, pki.ErrDocumentTooLarge)` 识别超限。[尺寸预检与签名](../pki/cms.go)

节点通过 `LocalCertificates.Object` 选择对象签名凭据。证书链中所有 DER 的长度加上叶证书的 `RawIssuer` 长度，合计上限为 24 KiB。创建节点、变更本机介绍的路由或端点、热加载凭据时，节点还会检查必需的介绍内容能否签发。超限更新返回错误，已有配置继续生效。签名介绍经 Base64 编码后随邻居通告装入 64 KiB 控制帧。[凭据装载](../identity.go) · [签名介绍](../introduction.go)
