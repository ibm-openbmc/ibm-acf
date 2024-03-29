
#include <CliTypes.h>
#include <CeLogin.h>

#include <string>
#include <vector>

#ifndef _CELOGINV1_H
#define _CELOGINV1_H

namespace CeLogin
{
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
    std::vector<cli::Machine> mMachines;
    std::string mExpirationDate;
    std::string mRequestId;
    const char* mPasswordPtr;
    std::size_t mPasswordLength;
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
    createCeLoginAcfV1Payload(const CeLoginCreateHsfArgsV1& argsParm,
                              std::string& generatedAcfParm,
                              std::vector<uint8_t>& generatedPayloadHashParm);

CeLoginRc
    createCeLoginAcfV1Signature(const CeLoginCreateHsfArgsV1& argsParm,
                                const std::vector<uint8_t>& jsonDigestParm,
                                std::vector<uint8_t>& generatedSignatureParm);

CeLoginRc createCeLoginAcfV1Asn1(const CeLoginCreateHsfArgsV1& argsParm,
                                 const std::string& jsonParm,
                                 const std::vector<uint8_t>& signatureParm,
                                 std::vector<uint8_t>& generatedAcfParm);

CeLoginRc
    decodeAndVerifyCeLoginHsfV1(const std::vector<uint8_t>& hsfParm,
                                const std::vector<uint8_t>& publicKeyParm,
                                CeLoginDecryptedHsfArgsV1& decodedHsfParm);

CeLoginRc generateRandomPassword(char* dstParm, const uint64_t dstSizeParm);

CeLogin::CeLoginRc getLocalRequestId(std::string& dstParm);

}; // namespace CeLogin

#endif
