# OpenSSL-Practice
Using OpenSSL API to implement some applications

## Deploy development environment
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
