#!/bin/bash

rm -f json.txt script.txt password.txt signature.bin acf.bin

echo Test Resource Dump ACF

echo -n "resourcedump command1; resourcedump command2;" > script.txt 

./build/celogin_cli create_prod -m P11,dev,UNSET -e 2035-05-01 -j json.txt -v2 -t resourcedump -f script.txt -n

openssl dgst -sign p11-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Resource Dump Acf"

./build/celogin_cli verify -i acf.bin -k p11-celogin-lab-pub.der -s UNSET

rm -f json.txt script.txt password.txt signature.bin acf.bin

echo Test Bmc Shell ACF

echo -n "bmcshell command1; bmcshell command2;" > script.txt 

./build/celogin_cli create_prod -m P11,dev,UNSET -e 2035-05-01 -j json.txt -v2 -t bmcshell -f script.txt -n -b 6000 -i

openssl dgst -sign p11-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Bmc Shell Acf"

./build/celogin_cli verify -i acf.bin -k p11-celogin-lab-pub.der -s UNSET

rm -f json.txt script.txt password.txt signature.bin acf.bin
