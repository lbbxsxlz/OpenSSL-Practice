# OpenSSL-Practice
Using OpenSSL API to implement some applications

## Deploy development environment
according to openssl-1.1.1g or OpenSSL 1.1.1  11 Sep 2018
```Bash
sudo apt-get install openssl
sudo apt-get install libssl-dev
```

```Bash
tar zxvf  openssl-1.1.1g.tar.gz;
cd openssl-1.1.1g;
./config;make

sudo make test
sudo make install
```

include header path: /usr/local/include/openssl

## openssl cmd
X509 certificate
```bash
 openssl genrsa -out t1.key 2048
 openssl req -new -in t1.key -out t1.csr
 openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
 openssl x509 -req -days 365 -in t1.csr -signkey key.pem -out t1.crt
 openssl x509 -in t1.crt -noout -text
openssl x509 -in cert.cer -inform DER -outform PEM -out cert.pem
```

## how to compile
```Bash
gcc rsaKey.c -o rsaKey -lcrypto
gcc hash.c -o hash -lcrypto
gcc hmac.c -o hmac -lcrypto
gcc genCert.c -o genCert -lcrypto
```
