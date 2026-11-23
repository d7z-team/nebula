# Go PKI 接口

企业 CA 和项目自带的 `nebula-pki` 均可签发符合下述配置的 X.509 v3 证书。Go 应用也可直接调用 `pki` 包，在进程内生成密钥、签发和验证证书。私钥文件使用 PKCS#8 PEM，外部签名器实现 `crypto.Signer`；CSR 使用 PKCS#10，证书使用 DER 或 PEM。[接入示例](quickstart.md) · [X.509](https://www.rfc-editor.org/rfc/rfc5280) · [PKCS#10](https://www.rfc-editor.org/rfc/rfc2986)

| 操作 | API | 调用方提供的材料 |
| --- | --- | --- |
| 生成密钥 | `pki.GenerateKey` 或 Go 标准库 | 内置便捷生成器支持 ed25519、p256、3072 位 RSA 和 ml-dsa-44。TLS 可用签名算法由 Go 和对端协商。 |
| 根与中间 CA | `CreateRoot`、`Issuer.IssueCA` | 根使用自己的签名器。签发中间 CA 时提供 CSR、获批主题、有效期和路径长度，校验 CA 密钥及上级约束。 |
| 申请与签发叶证书 | `CreateCSR`、`Issuer.IssueLeaf` | 申请者提交自签名 CSR。签发者以独立批准的 SPKI SHA-256、一个 IPv4 和一个 IPv6 SAN、网络、下游路由前缀、用途和有效期构造证书。CA 和叶密钥可以使用不同算法。 |
| 装载与验证 | `tls.LoadX509KeyPair`、`pki.ParseCertificates`、`pki.ParseKeyPEM`、`pki.VerifyChain` | 明确给出可信根、预期网络与完整地址对、用途与时刻，返回 Go 验证通过的候选路径。 |
| 签发与验证对象 | `pki.SignObject`、`pki.VerifyObjectSignature` | 提供用途、网络名和正文。验证签名后用 `VerifyChain` 建立对签名者的信任，再检查成员绑定和主题授权。节点的事件与介绍接收入口已完成上述检查。 |

## 证书配置

成员叶证书必须有两个 `iPAddress` SAN，分别用 4 字节编码 IPv4、16 字节编码原生 IPv6。证书中两项的顺序任意。mesh 扩展的 OID 为 `1.2.840.113556.1.8000.2554.26659.52563.57837.16539.38613.9490006.11144251`，关键性标志为 false。其 DER 值为以下 ASN.1 结构。

```asn1
MeshScope ::= SEQUENCE {
    network UTF8String,
    routedPrefixes SEQUENCE OF SEQUENCE { address OCTET STRING, bits INTEGER }
}
```

网络名使用 1 至 128 个小写 ASCII 字母、数字、下划线、点或连字符。前缀地址按网络序编码，主机位置零。普通节点使用空前缀序列。根或中间 CA 可以使用同一扩展限定可下放的网络和网段，缺省继承上级范围。CA 的标准 IP Name Constraints 另行限制叶证书 SAN。`CAProfile.Scope` 与 `PermittedIPs` 对应 CLI 的 `-network`、`-routes` 与 `-permit-ips`。每条候选路径单独验证。

签发节点证书时，`nebula-pki issue` 使用 `-network`、`-ipv4`、`-ipv6` 和经独立批准的 `-approved-key`。默认 `-role node` 同时包含 clientAuth、serverAuth、codeSigning。使用独立凭据时，分别以 `-role client`、`-role server`、`-role object` 签发同一地址对的三张证书，填入 `LocalCertificates.Client`、`Server`、`Object`。PEM 链从叶证书开始，随后依次放入中间 CA。验证单一用途时，给 `nebula-pki verify` 传入相应的 `-role`。[签发与验证示例](quickstart.md#签发证书)

通过 API 读取证书时，`pki.ReadIdentity(cert)` 提取声明，`pki.VerifyChain(chain, roots, network, peer, usage, now)` 验证其信任路径。签发有效期按 DER 的整秒精度检查。PKIX 验证包含到期时刻，节点的会话和缓存授权在到达截止时刻时失效。[证书边界测试](../pki/boundaries_test.go)

## 签名对象

CMS 使用 DER 编码的封装型 SignedData，包含一个 SignerInfo、叶证书和所提供的中间证书。签名属性包含 content-type 与 message-digest。签名正文将网络、用途、叶证书的 SHA-256 和业务内容绑定在一起；发布者的网络成员 ID 位于业务内容中。实现覆盖 Ed25519、ECDSA、RSA 和 ML-DSA。签名证书与签发 CA 可以采用不同的算法。事件接收方逐次验证原发布者，转发者的连接身份只说明直接来源。[CMS 格式](https://www.rfc-editor.org/rfc/rfc5652) · [签名与解析](../pki/cms.go) · [签发与互操作测试](../pki/pki_test.go)

节点在创建或热加载凭据时，要求对象签名证书链中所有 DER 证书的字节数加上叶证书的 `RawIssuer` 长度合计不超过 24 KiB。CMS 也用签发者和序列号标识签名者，因此签发者名称需要单独计入。完整 CMS DER 的上限为 44 KiB。端点介绍随 JSON 通告传送，通告还须容纳观察地址等字段并满足 64 KiB 控制帧预算。使用较长的中间 CA 链或较大的密钥时，应按实际 DER 长度核算。若节点需要独立的发布证书，可通过 `LocalCertificates.Object` 配置。[凭据装载](../identity.go) · [CMS 尺寸限制](../pki/cms.go)
