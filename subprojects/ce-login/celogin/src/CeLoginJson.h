
#include "CeLoginUtil.h"

#include <CeLogin.h>

#ifndef _CELOGINJSON_H
#define _CELOGINJSON_H

namespace CeLogin
{

extern const char* JsonName_Version;
extern const char* JsonName_Machines;
extern const char* JsonName_HashedAuthCode;
extern const char* JsonName_Salt;
extern const char* JsonName_Expiration;
extern const char* JsonName_FrameworkEc;
extern const char* JsonName_SerialNumber;
extern const char* JsonName_RequestId;
extern const char* JsonName_ReplayId;
extern const char* JsonName_Iterations;
extern const char* JsonName_AdminAuthCode;
extern const char* JsonName_Type;

extern const char* JsonValue_AcfTypeService;
extern const char* JsonValue_AcfTypeAdminReset;

struct AntiReplayInfo
{
    AntiReplayInfo() : mReplayIdPresent(false), mReplayId(0)
    {}

    bool mReplayIdPresent;
    uint64_t mReplayId;
};

struct CeLoginJsonData
{
    CeLoginJsonData() :
        mVersion(CeLoginInvalidVersion), mType(AcfType_Invalid),
        mRequestedAuthority(ServiceAuth_None), mHashedAuthCodeLength(0),
        mAuthCodeSaltLength(0), mExpirationDate(), mIterations(0), mReplayInfo()
    {
        memset(&mHashedAuthCode, 0x00, sizeof(mHashedAuthCode));
        memset(&mAuthCodeSalt, 0x00, sizeof(mAuthCodeSalt));
    };

    AcfVersion mVersion;
    AcfType mType;
    ServiceAuthority mRequestedAuthority;
    uint8_t mHashedAuthCode[CeLogin_MaxHashedAuthCodeLength];
    uint64_t mHashedAuthCodeLength;
    uint8_t mAuthCodeSalt[CeLogin_MaxHashedAuthCodeSaltLength];
    uint64_t mAuthCodeSaltLength;
    CeLogin_Date mExpirationDate;
    uint64_t mIterations;
    uint8_t mAdminAuthCode[CeLogin_MaxHashedAuthCodeLength];
    uint64_t mAdminAuthCodeLength;
    AntiReplayInfo mReplayInfo;
};

CeLoginRc decodeJson(const char* jsonStringParm,
                     const uint64_t jsonStringLengthParm,
                     const char* serialNumberParm,
                     const uint64_t serialNumberLengthParm,
                     CeLoginJsonData& decodedJsonParm);

CeLoginRc isTimeExpired(const CeLoginJsonData* sJsonData, uint64_t& sExpirationTime,
                        const uint64_t timeSinceUnixEpocInSecondsParm);

}; // namespace CeLogin

#endif