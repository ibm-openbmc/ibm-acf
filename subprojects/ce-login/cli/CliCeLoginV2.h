
#include <CeLogin.h>
#include <CliCeLoginV1.h>
#include <CliTypes.h>

#include <string>
#include <vector>

#ifndef _CELOGINV2_H
#define _CELOGINV2_H

namespace CeLogin
{
/*
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
*/

struct CeLoginCreateHsfArgsV2
{
    CeLoginCreateHsfArgsV1 mV1Args;
    bool mNoReplayId;
    std::string mType;
    std::string mScript;
    uint64_t mBmcTimeout;
    bool mIssueBmcDump;
};

struct CeLoginDecryptedHsfArgsV2
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

CeLoginRc createCeLoginAcfV2(const CeLoginCreateHsfArgsV2& argsParm,
                             std::vector<uint8_t>& generatedAcfParm);

CeLoginRc
    createCeLoginAcfV2Payload(const CeLoginCreateHsfArgsV2& argsParm,
                              std::string& generatedAcfParm,
                              std::vector<uint8_t>& generatedPayloadHashParm);

CeLoginRc
    createCeLoginAcfV2Signature(const CeLoginCreateHsfArgsV2& argsParm,
                                const std::vector<uint8_t>& jsonDigestParm,
                                std::vector<uint8_t>& generatedSignatureParm);

CeLoginRc createCeLoginAcfV2Asn1(const CeLoginCreateHsfArgsV2& argsParm,
                                 const std::string& jsonParm,
                                 const std::vector<uint8_t>& signatureParm,
                                 std::vector<uint8_t>& generatedAcfParm);

CeLoginRc
    decodeAndVerifyCeLoginHsfV2(const std::vector<uint8_t>& hsfParm,
                                const std::vector<uint8_t>& publicKeyParm,
                                CeLoginDecryptedHsfArgsV2& decodedHsfParm);

AcfType getAcfTypeFromString(const std::string& typeStrParm);
}; // namespace CeLogin

#endif
