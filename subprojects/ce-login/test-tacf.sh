#!/bin/bash

echo "NOTE: Requires compilation with the additional compiler argument TOLERATE_TARGETED_ACF_REPLAY. This can be configured in meson.build."

echo Test admin reset ACF

rm -f json.txt script.txt password.txt signature.bin acf.bin

./build/celogin_cli create_prod -m P11,dev,UNSET -e 2035-05-01 -j json.txt  -p password.txt -v2 -t adminreset -n

openssl dgst -sign p11-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Admin Reset Acf"

PASSWORD=`cat password.txt`

./build/celogin_cli verify -i acf.bin -k p10-celogin-lab-pub.der -p $PASSWORD -s UNSET

rm -f json.txt script.txt password.txt signature.bin acf.bin

echo Test Resource Dump ACF

echo "resourcedump command1; resourcedump command2;" > script.txt 

./build/celogin_cli create_prod -m P11,dev,UNSET -e 2035-05-01 -j json.txt -p password.txt -v2 -t resourcedump -f script.txt -n

openssl dgst -sign p11-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Resource Dump Acf"

PASSWORD=`cat password.txt`

./build/celogin_cli verify -i acf.bin -k p10-celogin-lab-pub.der -p $PASSWORD -s UNSET

rm -f json.txt script.txt password.txt signature.bin acf.bin

echo Test Bmc Shell ACF

echo "bmcshell command1; bmcshell command2;" > script.txt 

./build/celogin_cli create_prod -m P11,dev,UNSET -e 2035-05-01 -j json.txt -p password.txt -v2 -t bmcshell -f script.txt -n

openssl dgst -sign p11-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Bmc Shell Acf"

PASSWORD=`cat password.txt`

./build/celogin_cli verify -i acf.bin -k p10-celogin-lab-pub.der -p $PASSWORD -s UNSET

rm -f json.txt script.txt password.txt signature.bin acf.bin
