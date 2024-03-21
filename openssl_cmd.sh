 # 需要输入密钥以及相关信息
 openssl req -x509 -newkey rsa:3072 -keyout rsa3072.pem -out cert.pem -days 365
 # 查看证书
 openssl x509 -in cert.pem -noout -text
 # 私钥导出公钥
 openssl rsa -in rsa3072.pem -pubout -out rsa3072.pem.pub
 # 生成签名
 openssl dgst -sha384 -sign rsa3072.pem -out data.bin.sig data.bin
 # 验证签名
 openssl dgst -sha384 -verify rsa3072.pem.pub -signature data.bin.sig data.bin
 # 证书格式转换
 openssl x509 -in cert.pem -inform PEM -outform DER -out cert.DER
