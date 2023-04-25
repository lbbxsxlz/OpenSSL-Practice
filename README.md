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

sign csr
```
openssl req -newkey rsa:3072 -new -nodes -x509 -days 365 -out rootca.crt -keyout rootca.key -subj "/C=CN/ST=ShangHai/L=MinHang/O=Intel/CN=localhost"
openssl rand -writerand .rnd
openssl genrsa -out alice.key 3072
openssl req -new -key alice.key -out alice.csr -subj "/C=CN/ST=Beijing/L=Haidian/O=Myexample/CN=alice"
openssl x509  -req -in alice.csr -extfile <(printf "subjectAltName=DNS:localhost.alice") -CA rootca.crt -CAkey rootca.key -days 365 -sha256 -CAcreateserial -out alice.crt
```
## aes encrypt and decrypt
![image](https://user-images.githubusercontent.com/16954002/151516046-be2b5c89-567c-4112-b455-8acbe97ecc67.png)
```bash
echo -n "Hello world, hello aes cipher!" > text
openssl enc -aes-256-cbc -e -in text -out text.enc -K 6D626564746C73206165732063697068657221 -iv C10F5DC70603548769AEFFB5C4A97597
hexdump -C text.enc
openssl enc -aes-256-cbc -d -in text.enc -out text.d -K 6D626564746C73206165732063697068657221 -iv C10F5DC70603548769AEFFB5C4A97597
cat text.d
```

```
openssl enc -aes-128-cbc -in uuid.txt -out uuid_en.txt -pass pass:AR-Dahua-IPC-General-17031000 -e
openssl enc -aes-128-cbc -in uuid_en.txt -out uuid_de.txt -pass pass:AR-Dahua-IPC-General-17031000 -d
```

## how to compile
```Bash
gcc rsaKey.c -o rsaKey -lcrypto
gcc hash.c -o hash -lcrypto
gcc hmac.c -o hmac -lcrypto
gcc genCert.c -o genCert -lcrypto
```
