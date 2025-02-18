# ibm-acf

Access Control File functions

## This repository depends on the following libraries and should be installed on build machine:

libpam, libssl, libsdplus

## To build the ibm-acf pam module run these commands:

```
meson setup build
ninja -C build
```

## To run ibm-acf pam module unit tests, enable the tests option

Note: tests=enabled disables creating the unmodified pam_ibmacf module

```
meson setup -Dtests=enabled build
or
meson configure -Dtests=enabled build

cd build
meson test
```

Test status should display location of log file to view in depth logs of test

### How to setup this feature

#### Overview

- To test this feature from scratch a private key, public key and ACF are
  required
- The private key is needed to generate the ACF
- Both the public key and ACF need to be uploaded onto the bmc if not already
  present
- To generate the ACF the ce_login utility must be built
- Once the corresponding public key and ACF files are uploaded then login can be
  performed with the service user and the password used during generation of the
  ACF

#### Step 1. Generate public and private keys

- Create the RSA keypair

```
openssl genrsa -out rsakeys.pem 2048
```

- Get public key

```
openssl rsa -in rsakeys.pem -pubout -outform DER -out rsapubkey.der
```

- Get private key

```
openssl rsa -in rsakeys.pem -outform DER -out rsaprivkey.der
```

#### Step 2. Build the celogin_cli utility

```
cd subprojects/ce-login
meson setup -Dlib=false -Dbin=true build
ninja -C build
```

#### Step 3. Generate the ACF

First get the serial number of the machine you would like to generate the ACF
for.

The value can be retrieved from BMC's web interface as such:\
Overview page > Server information > Serial number\
The value can also be retrieved from the BMC shell with the following command:

```
busctl get-property xyz.openbmc_project.Inventory.Manager /xyz/openbmc_project/inventory/system xyz.openbmc_project.Inventory.Decorator.Asset SerialNumber
```

The --machine argument can either be "x,x,UNSET" or the serial number fetched
from the BMC "x,x,123454321"

```
./celogin_cli create \
                --machine 'P10,dev,12345' \
                --sourceFileName "none" \
                --password "0penBmc" \
                --expirationDate "2025-12-25" \
                --requestId "1234" \
                --pkey ../p10-celogin-lab-pkey.der \
                --output ./service.acf
```

#### Step 4. Upload ACF and Pubkey to BMC

```
scp ./ACFFile.bin root@BMCIP:/etc/acf/service.acf
scp ./rsapubkey.der root@BMCIP:/etc/acf/ibmacf-dev.key
```

#### Step 5. Login with service user

```
ssh service@BMCIP
```

password:0penBmc

This should be successful.

#### Additional details on generating the ACF are contained in the ce-login subproject README.

#### Positive test case:

- Generate a DER encoded keypair
- Generate the ACF file (noting the password used)
- Upload the public key and acf file to the bmc as /etc/acf/ibmacf-dev.key and
  /etc/acf/service.acf respectively
- Login with one of supported interfaces as the service user
- Enter the password used in the creation of the ACF file

#### Negative test cases:

- ACF login inaccessable with non service user
- Login with invalid password
- If only using dev key, set field mode to enabled (busctl set-property
  xyz.openbmc_project.Software.BMC.Updater /xyz/openbmc_project/software
  xyz.openbmc_project.Control.FieldMode FieldModeEnabled b 1)
- Upload a mismatched ACF file/public key
- Set a serial number that doesn't match the machines serial number
- Set processing type to invalid value in ACF file
- Set date prior to date on BMC in ACF file
- Set FrameworkEc to invalid value in ACF file
