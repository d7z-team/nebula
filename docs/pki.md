# 节点身份与集群授权

一把节点私钥可用于多个集群。普通根 CA 直接签发节点证书和各集群的 CA。节点证书证明私钥持有者的身份；每个集群独立签发一份绑定同一公钥的授权。每个 `nebula.Node` 固定一个根和一张集群 CA，管理自己的拓扑、主地址和会话。[握手时序](mesh.md#tls-与成员身份)

| 凭据 | 签发者 | 内容和使用时机 |
| --- | --- | --- |
| 节点证书 | 普通根 | X.509 v3，主体为 `CN=mesh node`，公钥、数字签名用途、clientAuth、serverAuth 和私有节点 EKU（mesh 扩展 OID 后接 `.1`）。TLS 只发送这张叶证书。 |
| 集群 CA | 普通根 | 网络名、两个成员网段、可委派的路由和 VIP 范围。 |
| 站点 CA（可选） | 集群 CA 或其下级 | 收窄成员地址和业务权限的签发范围。 |
| 集群授权 | 集群 CA 或站点 CA | 同一节点公钥、双栈地址 SAN、网络权限及 codeSigning。在 TLS 建立后证明成员资格，也用作 CMS 签名叶。 |

`PeerID` 是公钥 SubjectPublicKeyInfo 的 DER 编码的 SHA-256 摘要，显示为 64 个小写十六进制字符。通过 `pki.NewPeerID(publicKey)` 计算，或者运行 `nebula-pki inspect -fingerprint -in node.pem`。同钥续签节点证书时，各集群原有的有效授权仍然可用。换钥会产生新的身份，需要为新公钥签发授权，并更新引用旧 ID 的宿主配置。

## 签发证书

以下命令在仓库根目录运行，生成双进程示例所用的凭据文件。示例在同一台机器上生成密钥。跨机器签发时，申请方保留私钥并提交 CSR，签发者通过可信渠道取得用于 `-approved-key` 的公钥指纹。

```sh
lab=$(mktemp -d)
go build -o "$lab/nebula-pki" ./cmd/nebula-pki
(
  set -eu
  cd "$lab"
  ./nebula-pki keygen -out root.key
  ./nebula-pki root -key root.key -name "Identity Root" -path-len 2 -out root.pem
  ./nebula-pki keygen -out ca.key
  ./nebula-pki request -key ca.key -out ca.csr
  ./nebula-pki issue -role ca -cluster -network demo -name "Demo Cluster" -path-len 1 \
    -permit-ips 10.13.0.0/24,fd13::/64 -ca root.pem -ca-key root.key -in ca.csr \
    -approved-key "$(./nebula-pki inspect -in ca.key -fingerprint)" -out ca.pem
  n=0
  for name in alice bob; do
    n=$((n + 1))
    ./nebula-pki keygen -out "$name.key"
    ./nebula-pki request -key "$name.key" -out "$name.csr"
    id=$(./nebula-pki inspect -in "$name.key" -fingerprint)
    ./nebula-pki issue -role node -ca root.pem -ca-key root.key -in "$name.csr" \
      -approved-key "$id" -days 7 -out "$name.pem"
    ./nebula-pki issue -role grant -ca ca.pem -ca-key ca.key -in "$name.csr" \
      -approved-key "$id" -network demo -ipv4 "10.13.0.$n" -ipv6 "fd13::$n" -days 7 -out "$name.leaf"
    cat "$name.leaf" ca.pem > "$name.grant"
    ./nebula-pki verify -root root.pem -peer "$id" -in "$name.pem"
    ./nebula-pki verify -role grant -root root.pem -cluster-ca ca.pem -peer "$id" -in "$name.grant"
  done
)
```

`pki.GenerateKey`、`CreateRoot`、`CreateCSR`、`Issuer.IssueCA`、`Issuer.IssueNode`、`Issuer.IssueGrant` 提供对应 Go API。密钥采用 PKCS#8，申请采用 PKCS#10，签发者可以接入 `crypto.Signer`。`VerifyNode` 校验根直签和节点角色，`VerifyGrant` 检查公钥绑定、固定集群、PKIX 路径和委派约束。运行 `go run ./examples/pki` 可验证经站点 CA 签发的授权。[Go 示例](../examples/pki/main.go) · [X.509](https://www.rfc-editor.org/rfc/rfc5280) · [双进程接入](quickstart.md#使用磁盘凭据启动两个进程)

## 证书配置

对接外部 PKI 时，在 `Auth.RootCA` 配置普通自签根，成员网段及 mesh 权限由集群 CA 声明。可用 `pki.ValidateRoot` 检查根的配置。根直接签发节点叶，按上表设置唯一主体属性、数字签名用途及三个 EKU。`VerifyNode` 接受的 X.509 扩展为密钥用途、扩展密钥用途、基本约束、主体密钥标识和颁发者密钥标识。TLS 证书链只装入这张叶。[节点证书验证](../pki/pki.go)

集群授权叶证书必须有两个 `iPAddress` SAN，分别用 4 字节编码 IPv4、16 字节编码原生 IPv6。证书中两项的顺序任意。mesh 扩展的 OID 为 `1.2.840.113556.1.8000.2554.26659.52563.57837.16539.38613.9490006.11144251`，关键性标志为 false。其 DER 值为以下 ASN.1 结构。

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
| 集群 CA | `issue -role ca -cluster -network demo -permit-ips IPv4网段,IPv6网段` 固定两个成员网段。可用 `-routes` 和 `-anycast-pools` 分别委派下游路由和服务池。 | `memberIPv4`、`memberIPv6` |
| 站点 CA | `issue -role ca -permit-ips IPv4范围,IPv6范围` 指定双栈签发范围，同族可列多段。每段须在上级许可内，并避开上级排除范围。仅签发普通成员时，指定 `-network` 并留空路由和服务池。 | `permittedIPs` |
| 集群授权 | `issue -role grant` 将两个主地址写入 SAN。用 `-routes` 授权下游前缀，用 `-anycast-ips` 授权精确服务地址。 | `peer`、`routes`、`anycastIPs` |

CA 的 X.509 名称约束用 `permittedSubtrees` 指定可签发的主地址范围，用 `excludedSubtrees` 排除范围。签发和验证授权时会检查签发链上的约束。宿主负责从可用范围内预留地址对。[集群地址分配](addressing.md#签发和分配)

## 热加载与宿主授权

用 `tls.LoadX509KeyPair` 将节点叶和私钥读入 `LocalCertificates.Node`。用 `pki.ParseCertificatesPEM` 读取授权链，把每个证书的 `Raw` 按授权叶、站点 CA、集群 CA 的顺序放入 `LocalCertificates.Grant`。更新其中一项后，将整组材料传给 `node.ReloadCertificates(ctx, set)`。验证失败会保留原凭据。已经建立的连接按当次握手的身份和授权复查；`node.Paths()` 分别给出 `NodeSerial`、`GrantSerial` 和本端的对应序列号。

宿主用 `Options.Auth.CheckChain` 检查通过验证的证书路径。`Purpose` 区分 `NodeIdentity` 与 `ClusterGrant`。返回错误会拒绝该路径，非零时间可缩短有效期，零时间沿用证书链的期限。撤回单张证书可匹配 DER 指纹或签发者和序列号。

私钥泄露时，匹配 `check.Member` 可覆盖同一公钥的续证、两个握手方向和签名对象。宿主负责保存并分发决定，在创建节点前载入，运行中更新后调用 `Revalidate`。[本机生效范围](integration.md#选择本机安全策略)

```go
var denied sync.Map // nebula.PeerID keys
opts.Auth.CheckChain = func(ctx context.Context, check nebula.ChainCheck) (time.Time, error) {
    if _, found := denied.Load(check.Member); found {
        return time.Time{}, errors.New("member key withdrawn")
    }
    return time.Time{}, ctx.Err()
}

// Apply a host decision to a running node.
denied.Store(peerID, struct{}{})
if err := node.Revalidate(ctx); err != nil {
    return err
}
```

## 签名对象

介绍和主题消息使用 CMS（Cryptographic Message Syntax）的封装型 SignedData。签名覆盖网络名、用途、签名叶指纹、完整 DER 证书集合的摘要和业务正文。CMS 附原节点叶、授权叶和授权签发链。验证转发或补发的对象时，先用 `VerifyObjectSignature` 校验域、签名和证书集合，再将返回的证书交给 `VerifyObjectSigner`。后者验证身份和授权路径并核对同一公钥。宿主再检查实际发布者、授权期限和主题。节点的订阅 API 已完成这些检查。[独立验签示例](../pki/example_test.go) · [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652)

`CheckObjectSize` 可按签名算法的最大签名长度预检完整 CMS 的 44 KiB 上限，超限返回 `ErrDocumentTooLarge`。节点叶证书、授权链的 DER 及授权叶的 `RawIssuer` 合计上限为 24 KiB。新建、热加载及拓扑更新同时校验本机必需的介绍能否装入控制帧。[尺寸预检](../pki/cms.go)
