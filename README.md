# Vcoin 1.0.0

 **What is Vcoin?**

Vcoin is an implementation of the "Zerocash" protocol. Based on Bitcoin's code, it intends to offer a far higher standard of privacy through a sophisticated zero-knowledge proving scheme that preserves confidentiality of transaction metadata.

This software is the Vcoin node and command-line client. It downloads and stores the entire history of Vcoin transactions; depending on the speed of your computer and network connection, the synchronization process could take a day or more once the blockchain has reached a significant size.

* **P2P Port -** 16325  
* **RPC Port -** 16324


## Build (Ubuntu 16.04 Tested)
1. Get dependencies
```
sudo apt-get update
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake curl
```

2. Build
```
# pull
git clone https://github.com/lubhub612/vcoin.git
cd vcoin
# Build
./zcutil/build.sh -j$(nproc)
```

#### Run Vcoin 
1. Create vcoin.conf file
```
mkdir -p  ~/.vcoin
echo "rpcuser=username" >> ~/.vcoin/vcoin.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/.vcoin/vcoin.conf
echo "addnode=206.189.93.248" >> ~/.vcoin/vcoin.conf
echo "addnode=178.128.49.88" >> ~/.vcoin/vcoin.conf
echo "addnode=165.22.98.132" >> ~/.vcoin/vcoin.conf
echo "addnode=159.65.12.100" >> ~/.vcoin/vcoin.conf
please add those  command  in vcoin.conf file to complete vcoin.conf
cd ~/.vcoin
nano  vcoin.conf
listen=1
rpcport=16324
#rpcallowip=10.1.1.34
#rpcallowip=192.168.*.*
#rpcallowip=1.2.3.4/255.255.255.0
rpcallowip=127.0.0.1
rpctimeout=30
gen=1
equihashsolver=tromp
showmetrics=1
 #Use Secure Sockets Layer (also known as TLS or HTTPS) to communicate
# with vcoin -server or vcoind
#rpcssl=1
# OpenSSL settings used when rpcssl=1
#rpcsslciphers=TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH
#rpcsslcertificatechainfile=server.cert
#rpcsslprivatekeyfile=server.pem


```

2. Fetch keys
```
cd vcoin
./zcutil/fetch-params.sh
```

3. Run a Vcoin node
```
./src/vcoind 
```