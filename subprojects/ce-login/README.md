# ce-login
Ce-Login depends on the following libraries and should be installed on build machine:

libcrypto, libssl, json-c (celogin_cli)

To build the ce-login utility run these commands:
```
meson setup -Dlib=false -Dbin=true build
ninja -C build
```

To build the ce-login static utility openssl and json-c will need to be statically compiled:

Openssl static build example:
```
git clone https://github.com/openssl/openssl.git
cd openssl
OPENSSL_INSTALL_DIR=$PWD/install
./Configure no-sock no-threads no-shared no-stdio no-dso --prefix=$OPENSSL_INSTALL_DIR --openssldir=$PWD/ssl
THREADS=$(grep -c   "^processor" /proc/cpuinfo)
make -j$(THREADS)
make install -j$(THREADS)
```
Json-c static build example:
```
git clone https://github.com/json-c/json-c
cd json-c
JSON_DIR=$PWD
mkdir install
cmake -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$JSON_DIR/install
THREADS=$(grep -c   "^processor" /proc/cpuinfo)
make -j$(THREADS)
make install -j$(THREADS)
```
Note: PKG_CONFIG_PATH needs to be set if dependencies openssl and json-c are not statically
    compiled and not installed in the standard location

Otherwise, you should be able to run the next command without setting the PKG_CONFIG_PATH env var
```
PKG_CONFIG_PATH=$JSON_DIR:$OPENSSL_INSTALL_DIR/lib64/pkgconfig/ \
    meson setup -Dlib=false -Dstatic-bin=true build
ninja -C build
```

Check that celogin_cli utility is statically compiled:
```
ldd ./build/celogin_cli
>   not a dynamic executable
```

There is support to build either the cli utility, static lib or shared lib.

The options can be configured on setup or afterwards with the 'meson configure' command

Set any of the options to 'true' to build desired target
```
meson configure -Dlib=[true | false] -Dbin=[true | false] -Dstatic-bin=[true | false] -Ddefault_library=[shared | static] build
```
Default configuration is:
```
-Dlib=true -Dbin=false -Ddefault_library=static
```
As defined by meson_options.txt

Running meson unit tests:
```
meson setup -Dlib=false -Dbin=true build
ninja -C build
cd build
meson test
```
Running celogin_cli unit tests:
```
./build/celogin_cli test
```

Example creation of pub/priv keys for this utility:

Create the RSA Private Key
```
openssl genrsa -out rsaprivkey.pem 2048
```
Get public key
```
openssl rsa -in rsaprivkey.pem -pubout -outform DER -out rsapubkey.der
```
Get private key
```
openssl rsa -in rsaprivkey.pem -outform DER -out rsaprivkey.der
```

Example usage of the celogin_cli utility:

Create ACF:
```
./build/celogin_cli create \
                --machine 'P10,dev,UNSET' \
                --password "0penBmc" \
                --expirationDate "2025-12-25" \
                --pkey ./p10-celogin-lab-pkey.der \
                --output ./service.acf
```

Verify ACF:
```
./build/celogin_cli verify \
                --hsfFile ./service.acf \
                --publicKeyFile ./p10-celogin-lab-pub.der \
                --password "0penBmc" \
                --serialNumber "UNSET"
```

Decode ACF - Decodes and prints contents of ACF:
```
./build/celogin_cli decode \
                --hsfFile ./service.acf \
                --publicKeyFile ./p10-celogin-lab-pub.der
```

Supported keyword value pairs:

machine: [ ProcessorGeneration (P10), ServiceAuthority (ce | dev), SerialNumber ( "UNSET" | bmc serial number )]\
expirationDate: [yyyy-mm-dd format only]\
password: [unrestricted]
