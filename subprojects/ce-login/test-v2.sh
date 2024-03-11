#/bin/bash

rm -f json.txt password.txt signature.bin acf.bin

#./build/celogin_cli create_prod -v2 -t adminreset -m P10,dev,UNSET -e 2023-05-01 -j json.txt  -p password.txt
#./build/celogin_cli create_prod -v2 -t service -m P10,dev,UNSET -e 2023-05-01 -j json.txt  -p password.txt -d digest.bin

#./build/celogin_cli create_prod -v2 -n -t service -m P10,dev,UNSET -e 2023-05-01 -j json.txt  -p password.txt -d digest.bin

./build/celogin_cli create_prod -v2 -t service -n -m P10,dev,13BE990 -m P10,dev,UNSET -e 2030-01-01 -j json.txt  -p password.txt
#./build/celogin_cli create_prod -v2 -t adminreset -m P10,dev,13BE990 -m P10,dev,UNSET -e 2024-01-01 -j json.txt  -p password.txt
#./build/celogin_cli create_prod -v2 -t service -m P10,dev,139B0C0 -e 2024-01-01 -j json.txt  -p password.txt -d digest.bin

# Note, when using openssl it is easier to just recreate the digest instead of passing in the existing one
openssl dgst -sign p10-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Acf"

PASSWORD=`cat password.txt`

./build/celogin_cli verify -i acf.bin -k p10-celogin-lab-pub.der -p $PASSWORD -s UNSET
