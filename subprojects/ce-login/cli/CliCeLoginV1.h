
#include <CeLogin.h>

#include <string>
#include <vector>

#ifndef _CELOGINV1_H
#define _CELOGINV1_H

namespace CeLogin
{
enum ProcessorGeneration
{
    Invalid = 0,
    P10 = 10,
};

struct Machine
{
    Machine() : mSerialNumber(), mAuth(ServiceAuth_None), mProc(Invalid)
    {}

    Machine(const std::string& serialNumberParm,
            const CeLogin::ServiceAuthority authParm,
            const ProcessorGeneration procGenParm) :
        mSerialNumber(serialNumberParm),
        mAuth(authParm), mProc(procGenParm)
    {}
    std::string mSerialNumber;
    CeLogin::ServiceAuthority mAuth;
    ProcessorGeneration mProc;
};

struct DecodedMachine
{
    std::string mSerialNumber;
    std::string mFrameworkEc;
};

enum PasswordHashAlgorithm
{
    PasswordHash_Production,
    PasswordHash_SHA512,
};

struct CeLoginCreateHsfArgsV1
{
    std::string mSourceFileName;
    std::vector<CeLogin::Machine> mMachines;
    std::string mExpirationDate;
    std::string mRequestId;
    std::string mPassword;
    PasswordHashAlgorithm mPasswordHashAlgorithm;
    std::vector<uint8_t> mPrivateKey;
    std::size_t mSaltLength;
    std::size_t mHashedAuthCodeLength;
    std::size_t mIterations;
};

struct CeLoginDecryptedHsfArgsV1
{
    std::string mProcessingType;
    std::string mSourceFileName;
    std::vector<uint8_t> mSignedPayload;
    std::vector<uint8_t> mSignature;
    std::vector<DecodedMachine> mMachines;
    std::string mExpirationDate;
    std::string mRequestId;
    std::string mPasswordHash;
    std::string mSalt;
    int mIterations;
};

CeLoginRc createCeLoginAcfV1(const CeLoginCreateHsfArgsV1& argsParm,
                             std::vector<uint8_t>& generatedAcfParm);

CeLoginRc
    decodeAndVerifyCeLoginHsfV1(const std::vector<uint8_t>& hsfParm,
                                const std::vector<uint8_t>& publicKeyParm,
                                CeLoginDecryptedHsfArgsV1& decodedHsfParm);

}; // namespace CeLogin

#endif
