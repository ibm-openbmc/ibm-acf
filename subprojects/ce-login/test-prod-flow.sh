#/bin/bash

rm -f json.txt password.txt signature.bin acf.bin

./build/celogin_cli create_prod -m P10,dev,1234567 -e 2030-01-03 -j json.txt  -p password.txt # -d digest.bin

# Note, when using openssl it is easier to just recreate the digest instead of passing in the existing one
openssl dgst -sign p10-celogin-lab-pkey.der -sha512 -keyform DER -out signature.bin  json.txt

./build/celogin_cli create_prod -j json.txt -s signature.bin -o acf.bin -c "Test Acf"

PASSWORD=`cat password.txt`

./build/celogin_cli verify -i acf.bin -k p10-celogin-lab-pub.der -p $PASSWORD -s 1234567
