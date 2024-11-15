
#include "CeLoginJson.h"

#include "CeLoginUtil.h"
#include "JsmnUtils.h"

#include <CeLogin.h>
#include <string.h>

using namespace CeLogin;

namespace JsonUtils
{
enum JsonUtilsRc
{
    Success = CeLoginRc::Success,

    DecodeJson_JsmnParseFailed = 0x10,
    DecodeJson_JsonRootNotObject = 0x11,

    ParseDate_InvalidParm = 0x20,
    ParseDate_NotString = 0x21,

    ParseHashedAuth_InvalidParm = 0x30,
    ParseHashedAuth_NotString = 0x31,
    ParseHashedAuth_UnexpectedHashLength = 0x31,

    ParseAuthFromMachineArray_InvalidParm = 0x40,
    ParseAuthFromMachineArray_NotAnArray = 0x41,
    ParseAuthFromMachineArray_InvalidFrameworkEc = 0x42,

    ParseSalt_InvalidParm = 0x50,
    ParseSalt_NotString = 0x51,
    ParseSalt_SaltTooLong = 0x52,

    ParseIterations_InvalidParm = 0x60,
    ParseIterations_NotPrimitive = 0x61,
};

enum
{
    JsmnMaxNumTokens = 128,
};
}; // namespace JsonUtils

static CeLoginRc ParseDateFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                                    const uint64_t expirationTokenIdxParm,
                                    CeLogin_Date& dateParm);

static CeLoginRc ParseAuthorityFromMachineArrayToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t machineArrayTokenIdxParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm, ServiceAuthority& authorityParm);

static CeLoginRc ParseHashedAuthCodeFromToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t hashedAuthCodeTokenIdxParm, uint8_t* hashedAuthCodeParm,
    const uint64_t hashedAuthCodeSizeParm, uint64_t& bytesWrittenParm);

static CeLoginRc ParseSaltFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                                    const uint64_t saltTokenIdxParm,
                                    uint8_t* saltParm,
                                    const uint64_t saltSizeParm,
                                    uint64_t& bytesWrittenParm);

static CeLoginRc
    ParseIterationsFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                             const uint64_t saltTokenIdxParm,
                             uint64_t& iterationsParm);

// machines and expiration
static CeLoginRc ParseCommonAcfFields(const JsmnUtils::JsmnState& jsmnStateParm,
                                      CeLogin_Date& dateParm,
                                      const char* serialNumberParm,
                                      const uint64_t serialNumberLengthParm,
                                      ServiceAuthority& authorityParm);

static CeLoginRc ParseServiceLoginFields(
    const JsmnUtils::JsmnState& jsmnStateParm, const AcfVersion versionParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    CeLoginJsonData& decodedJsonParm);

static CeLoginRc ParseAdminResetFields(
    const JsmnUtils::JsmnState& jsmnStateParm, const AcfVersion versionParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    CeLoginJsonData& decodedJsonParm);

static CeLoginRc ParseResourceDumpFields(
    const JsmnUtils::JsmnState& jsmnStateParm, const AcfVersion versionParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    CeLoginJsonData& decodedJsonParm);

static CeLoginRc ParseBmcShellFields(const JsmnUtils::JsmnState& jsmnStateParm,
                                     const AcfVersion versionParm,
                                     const char* serialNumberParm,
                                     const uint64_t serialNumberLengthParm,
                                     CeLoginJsonData& decodedJsonParm);

CeLoginRc CeLogin::decodeJson(const char* jsonStringParm,
                              const uint64_t jsonStringLengthParm,
                              const char* serialNumberParm,
                              const uint64_t serialNumberLengthParm,
                              CeLoginJsonData& decodedJsonParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    AcfVersion sVersion = CeLoginInvalidVersion;
    AcfType sAcfType = AcfType_Invalid;

    // Used to parse fields in the highest level json object
    const uint64_t sRootObjectTokenIdx = 0;

    jsmn_parser sJsmnParser;
    jsmntok_t sJsmnTokens[JsonUtils::JsmnMaxNumTokens];

    jsmn_init(&sJsmnParser);
    int sNumTokens = jsmn_parse(&sJsmnParser, jsonStringParm,
                                jsonStringLengthParm, sJsmnTokens, 128);

    if (sNumTokens <= 0)
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::DecodeJson_JsmnParseFailed);
    }

    // This is a hardcoded parser. It expects the ACF JSON to look something
    // like this (for a service ACF):
    // {
    //     "version":2,
    //     "type":"service",
    //     "machines":
    //         [
    //             { "serialNumber":"000020012345", "frameworkEc":"PWR10S" },
    //             { "serialNumber":"UNSET", "frameworkEc":"PWR10D" }
    //         ],
    //     "hashedAuthCode":"xxxxxxxx",
    //     “salt”:”xxxxxxxxx”,
    //     “iterations”:”10000”,
    //     "expiration":"2018-12-25",
    //     "requestId":"FACE0FF0",
    //     "replayId":"153623423"
    // }

    // Wrap the json string and tokens array in a nice way
    JsmnUtils::JsmnState sJsmnState;
    sJsmnState.mJsonString = jsonStringParm;
    sJsmnState.mJsonStringLength = jsonStringLengthParm;
    sJsmnState.mTokenArray = sJsmnTokens;
    sJsmnState.mTokenArrayLength = sNumTokens;

    // Step 1: Examine the top level entity. JSON only allows for a single
    // top-level entity. In the case of CeLogin, it must be an Object.
    if (CeLoginRc::Success == sRc)
    {
        if (JSMN_OBJECT != sJsmnTokens[0].type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::DecodeJson_JsonRootNotObject);
        }
    }

    // Step 2: Now that we know it is an Object, look for the "Names" associated
    // with all of the "Values" in the top level object. For CeLogin, we first
    // parse the attributes that are common to all ACF types:
    //      - "version"
    //      - "expiration"
    //      - "replayid"
    //      - "machines"
    //      - "type"
    // For the service ACF, we also have the following fields:
    //      - "hashedAuthCode"
    //      - "salt"
    //      - "iterations"
    // For the admin reset ACF, we also have the following fields:
    //      - "adminAuthCode"
    // Any others are ignored. If a duplicate is detected, then an error will be
    // returned.

    uint64_t sVersionIdx = 0;
    uint64_t sTypeIdx = 0;
    uint64_t sReplayIdIdx = 0;

    // Parse Version first, before parsing other things. Validate that the
    // version is correct before attempting to parse anything else
    if (CeLoginRc::Success == sRc)
    {
        uint64_t sParsedVersion = 0;

        // Get the token for the version integer
        JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            sJsmnState, sRootObjectTokenIdx, JsonName_Version,
            strlen(JsonName_Version), sVersionIdx);
        sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

        // Parse the string from the token into an unsigned integer
        if (CeLoginRc::Success == sRc)
        {
            JsmnUtils::JsmnString sVersionString =
                sJsmnState.getString(sVersionIdx);
            sRc = getUnsignedIntegerFromString(sVersionString.mCharArray,
                                               sVersionString.mCharLength,
                                               sParsedVersion);
        }

        if (CeLoginRc::Success == sRc)
        {
            if (CeLoginVersion1 == sParsedVersion ||
                CeLoginVersion2 == sParsedVersion)
            {
                sVersion = (AcfVersion)sParsedVersion;
                decodedJsonParm.mVersion = sVersion;
            }
            else
            {
                sRc = CeLoginRc::UnsupportedVersion;
            }
        }
    }

    // Parse ACF type first, if it exists
    if (CeLoginRc::Success == sRc)
    {
        if (CeLoginVersion1 == sVersion)
        {
            // Version one only supports service ACFs
            sAcfType = AcfType_Service;
        }
        else
        {
            JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::ObjectGetValueByKey(
                sJsmnState, sRootObjectTokenIdx, JsonName_Type,
                strlen(JsonName_Type), sTypeIdx);

            if (JsmnUtils::Success == sJsmnRc)
            {
                JsmnUtils::JsmnString sTypeStr = sJsmnState.getString(sTypeIdx);
                if (JsmnUtils::SafeJsmnStringCompare(
                        sTypeStr, JsonValue_AcfTypeService,
                        strlen(JsonValue_AcfTypeService)))
                {
                    sAcfType = AcfType_Service;
                }
                else if (JsmnUtils::SafeJsmnStringCompare(
                             sTypeStr, JsonValue_AcfTypeAdminReset,
                             strlen(JsonValue_AcfTypeAdminReset)))
                {
                    sAcfType = AcfType_AdminReset;
                }
                else if (JsmnUtils::SafeJsmnStringCompare(
                             sTypeStr, JsonValue_AcfTypeResourceDump,
                             strlen(JsonValue_AcfTypeResourceDump)))
                {
                    sAcfType = AcfType_ResourceDump;
                }
                else if (JsmnUtils::SafeJsmnStringCompare(
                             sTypeStr, JsonValue_AcfTypeBmcShell,
                             strlen(JsonValue_AcfTypeBmcShell)))
                {
                    sAcfType = AcfType_BmcShell;
                }
                else
                {
                    sRc = CeLoginRc::UnsupportedAcfType;
                }
            }
            else
            {
                sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                sAcfType = AcfType_Invalid;
            }
        }

        decodedJsonParm.mType = sAcfType;
    }

    // Parse replay ID if exists
    if (CeLoginRc::Success == sRc && sVersion == CeLoginVersion2)
    {
        JsmnUtils::JsmnUtilRc sTmpRc = JsmnUtils::ObjectGetValueByKey(
            sJsmnState, sRootObjectTokenIdx, JsonName_ReplayId,
            strlen(JsonName_ReplayId), sReplayIdIdx);

        if (JsmnUtils::Success == sTmpRc)
        {
            decodedJsonParm.mReplayInfo.mReplayIdPresent = true;
            JsmnUtils::JsmnString sReplayIdStr =
                sJsmnState.getString(sReplayIdIdx);
            sRc = CeLogin::getUnsignedIntegerFromString(
                sReplayIdStr.mCharArray, sReplayIdStr.mCharLength,
                decodedJsonParm.mReplayInfo.mReplayId);
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        switch (sAcfType)
        {
            case AcfType_AdminReset:
            {
                sRc = ParseAdminResetFields(
                    sJsmnState, sVersion, serialNumberParm,
                    serialNumberLengthParm, decodedJsonParm);
                break;
            }
            case AcfType_Service:
            {
                sRc = ParseServiceLoginFields(
                    sJsmnState, sVersion, serialNumberParm,
                    serialNumberLengthParm, decodedJsonParm);
                break;
            }
            case AcfType_ResourceDump:
            {
                sRc = ParseResourceDumpFields(
                    sJsmnState, sVersion, serialNumberParm,
                    serialNumberLengthParm, decodedJsonParm);
                break;
            }
            case AcfType_BmcShell:
            {
                sRc = ParseBmcShellFields(
                    sJsmnState, sVersion, serialNumberParm,
                    serialNumberLengthParm, decodedJsonParm);
                break;
            }
            default:
                break;
        }
    }

    return sRc;
}

CeLoginRc ParseDateFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                             const uint64_t expirationTokenIdxParm,
                             CeLogin_Date& dateParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(expirationTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseDate_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(expirationTokenIdxParm);

        if (JSMN_STRING != sTokenValue.type)
        {
            sRc =
                CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseDate_NotString);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(expirationTokenIdxParm);
            sRc = getDateFromString(sJsmnString.mCharArray,
                                    sJsmnString.mCharLength, dateParm);
        }
    }
    return sRc;
}

CeLoginRc ParseAuthorityFromMachineArrayToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t machineArrayTokenIdxParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm, ServiceAuthority& authorityParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(machineArrayTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::ParseAuthFromMachineArray_InvalidParm);
    }
    else
    {
        // Instead of trying to parse the entire machines array into some kind
        // of structure, scan it for the specific serial number that we care
        // about.
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(machineArrayTokenIdxParm);

        if (JSMN_ARRAY != sTokenValue.type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::ParseAuthFromMachineArray_NotAnArray);
        }
        else
        {
            bool sIsSerialNumberFound = false;
            const uint64_t sNumOfEntries = sTokenValue.size; // Array length
            uint64_t sCurIdx =
                machineArrayTokenIdxParm + 1; // Next token is the first element
            for (uint64_t sIdx = 0; sIdx < sNumOfEntries;
                 sIdx++) // Iterate over the array
            {
                // It should be an array of objects. Each object contains a
                // "serialNumber" and "frameworkEc" pair. First find the serial
                // number.
                uint64_t sSerialNumberIdx = 0;
                if (CeLoginRc::Success == sRc)
                {
                    JsmnUtils::JsmnUtilRc sJsmnRc =
                        JsmnUtils::ObjectGetValueByKey(
                            jsmnStateParm, sCurIdx, JsonName_SerialNumber,
                            strlen(JsonName_SerialNumber), sSerialNumberIdx);
                    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                }

                if (CeLoginRc::Success == sRc)
                {
                    // If the serial number was successfully read, compare to
                    // the requested serial number
                    JsmnUtils::JsmnString sSerialNumber =
                        jsmnStateParm.getString(sSerialNumberIdx);

                    if (JsmnUtils::SafeJsmnStringCompare(
                            sSerialNumber, serialNumberParm,
                            serialNumberLengthParm))
                    {
                        sIsSerialNumberFound = true;
                        // This is the entry for the current system
                        uint64_t sFrameworkEcIdx = 0;
                        {
                            // Locate the frameworkEc
                            JsmnUtils::JsmnUtilRc sJsmnRc =
                                JsmnUtils::ObjectGetValueByKey(
                                    jsmnStateParm, sCurIdx,
                                    JsonName_FrameworkEc,
                                    strlen(JsonName_FrameworkEc),
                                    sFrameworkEcIdx);
                            sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                        }

                        // If the frameworkEc was located, determine the service
                        // authority
                        if (CeLoginRc::Success == sRc)
                        {
                            JsmnUtils::JsmnString sFrameworkEc =
                                jsmnStateParm.getString(sFrameworkEcIdx);
                            sRc = CeLogin::getServiceAuthorityFromFrameworkEc(
                                sFrameworkEc.mCharArray,
                                sFrameworkEc.mCharLength, authorityParm);
                            // Regardless of the outcome, the serial number was
                            // located. Either we got an authority or an error
                            // occured. Stop looking.
                            break;
                        }
                    }
                }

                // If no errors, find the next array index
                if (CeLoginRc::Success == sRc)
                {
                    uint64_t sNextIdx = 0;
                    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::GetNextJsonEntry(
                        jsmnStateParm, sCurIdx, sNextIdx);
                    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);
                    sCurIdx = sNextIdx;
                }

                if (CeLoginRc::Success != sRc)
                {
                    // An error occurred this iteration, exit
                    break;
                }
            }
            if (CeLoginRc::Success == sRc && !sIsSerialNumberFound)
            {
                sRc = CeLoginRc::SerialNumberMismatch;
            }
        }
    }
    return sRc;
}

CeLoginRc ParseHashedAuthCodeFromToken(
    const JsmnUtils::JsmnState& jsmnStateParm,
    const uint64_t hashedAuthCodeTokenIdxParm, uint8_t* hashedAuthCodeParm,
    const uint64_t hashedAuthCodeSizeParm, uint64_t& bytesWrittenParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    bytesWrittenParm = 0;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(hashedAuthCodeTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::ParseHashedAuth_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(hashedAuthCodeTokenIdxParm);

        if (JSMN_STRING != sTokenValue.type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::ParseHashedAuth_NotString);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(hashedAuthCodeTokenIdxParm);

            sRc = getBinaryFromHex(sJsmnString.mCharArray,
                                   sJsmnString.mCharLength, hashedAuthCodeParm,
                                   hashedAuthCodeSizeParm, bytesWrittenParm);

            if (CeLoginRc::Success == sRc &&
                CeLogin_MaxHashedAuthCodeLength < bytesWrittenParm)
            {
                sRc =
                    CeLoginRc(CeLoginRc::JsonUtils,
                              JsonUtils::ParseHashedAuth_UnexpectedHashLength);
            }
        }
    }
    return sRc;
}

CeLoginRc ParseSaltFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                             const uint64_t saltTokenIdxParm, uint8_t* saltParm,
                             const uint64_t saltSizeParm,
                             uint64_t& bytesWrittenParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    bytesWrittenParm = 0;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(saltTokenIdxParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseSalt_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue = jsmnStateParm.getToken(saltTokenIdxParm);

        if (JSMN_STRING != sTokenValue.type)
        {
            sRc =
                CeLoginRc(CeLoginRc::JsonUtils, JsonUtils::ParseSalt_NotString);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(saltTokenIdxParm);

            sRc = getBinaryFromHex(sJsmnString.mCharArray,
                                   sJsmnString.mCharLength, saltParm,
                                   saltSizeParm, bytesWrittenParm);

            if (CeLoginRc::Success == sRc &&
                CeLogin_MaxHashedAuthCodeSaltLength < bytesWrittenParm)
            {
                sRc = CeLoginRc(CeLoginRc::JsonUtils,
                                JsonUtils::ParseSalt_SaltTooLong);
            }
        }
    }
    return sRc;
}

CeLoginRc ParseIterationsFromToken(const JsmnUtils::JsmnState& jsmnStateParm,
                                   const uint64_t iterationsTokenIdxParm,
                                   uint64_t& iterationsParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    if (!jsmnStateParm.isValid() ||
        !jsmnStateParm.isTokenIdxValid(iterationsParm))
    {
        sRc = CeLoginRc(CeLoginRc::JsonUtils,
                        JsonUtils::ParseIterations_InvalidParm);
    }
    else
    {
        const jsmntok_t& sTokenValue =
            jsmnStateParm.getToken(iterationsTokenIdxParm);

        if (JSMN_PRIMITIVE != sTokenValue.type)
        {
            sRc = CeLoginRc(CeLoginRc::JsonUtils,
                            JsonUtils::ParseIterations_NotPrimitive);
        }
        else
        {
            JsmnUtils::JsmnString sJsmnString =
                jsmnStateParm.getString(iterationsTokenIdxParm);

            sRc = getUnsignedIntegerFromString(sJsmnString.mCharArray,
                                               sJsmnString.mCharLength,
                                               iterationsParm);
        }
    }
    return sRc;
}

CeLoginRc ParseServiceLoginFields(const JsmnUtils::JsmnState& jsmnStateParm,
                                  const AcfVersion versionParm,
                                  const char* serialNumberParm,
                                  const uint64_t serialNumberLengthParm,
                                  CeLoginJsonData& decodedJsonParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;

    const uint64_t sRootObjectTokenIdx = 0;

    uint64_t sHashedAuthCodeIdx = 0;
    uint64_t sSaltIdx = 0;
    uint64_t sIterationsIdx = 0;

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_HashedAuthCode,
            strlen(JsonName_HashedAuthCode), sHashedAuthCodeIdx);
    }

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_Salt,
            strlen(JsonName_Salt), sSaltIdx);
    }

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_Iterations,
            strlen(JsonName_Iterations), sIterationsIdx);
    }

    // Convert JsmnRc to CeLoginRc for consolidated RC handling
    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseCommonAcfFields(
            jsmnStateParm, decodedJsonParm.mExpirationDate, serialNumberParm,
            serialNumberLengthParm, decodedJsonParm.mRequestedAuthority);
    }

    // parse hashed auth code
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseHashedAuthCodeFromToken(
            jsmnStateParm, sHashedAuthCodeIdx, decodedJsonParm.mHashedAuthCode,
            sizeof(decodedJsonParm.mHashedAuthCode),
            decodedJsonParm.mHashedAuthCodeLength);
    }

    // parse salt
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseSaltFromToken(jsmnStateParm, sSaltIdx,
                                 decodedJsonParm.mAuthCodeSalt,
                                 sizeof(decodedJsonParm.mAuthCodeSalt),
                                 decodedJsonParm.mAuthCodeSaltLength);
    }

    // parse number of iterations
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseIterationsFromToken(jsmnStateParm, sIterationsIdx,
                                       decodedJsonParm.mIterations);
    }

    return sRc;
}

CeLoginRc ParseAdminResetFields(const JsmnUtils::JsmnState& jsmnStateParm,
                                const AcfVersion versionParm,
                                const char* serialNumberParm,
                                const uint64_t serialNumberLengthParm,
                                CeLoginJsonData& decodedJsonParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;

    const uint64_t sRootObjectTokenIdx = 0;

    uint64_t sAdminAuthCodeIdx = 0;

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_AdminAuthCode,
            strlen(JsonName_AdminAuthCode), sAdminAuthCodeIdx);
    }

    // Convert to CeLoginRc for consolidated RC handling
    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

    if (CeLoginRc::Success == sRc)
    {
        ServiceAuthority sIgnoredAuth;
        sRc = ParseCommonAcfFields(
            jsmnStateParm, decodedJsonParm.mExpirationDate, serialNumberParm,
            serialNumberLengthParm, sIgnoredAuth);
    }

    // Copy out adminAuthCode
    if (CeLoginRc::Success == sRc)
    {
        JsmnUtils::JsmnString sAdminAuthStr =
            jsmnStateParm.getString(sAdminAuthCodeIdx);
        if (sAdminAuthStr.mCharLength <= CeLogin_MaxHashedAuthCodeLength)
        {
            memcpy(decodedJsonParm.mAdminAuthCode, sAdminAuthStr.mCharArray,
                   sAdminAuthStr.mCharLength);
            decodedJsonParm.mAdminAuthCodeLength = sAdminAuthStr.mCharLength;
        }
        else
        {
            sRc = CeLoginRc::Failure;
        }
    }

    return sRc;
}

CeLoginRc ParseResourceDumpFields(const JsmnUtils::JsmnState& jsmnStateParm,
                                  const AcfVersion versionParm,
                                  const char* serialNumberParm,
                                  const uint64_t serialNumberLengthParm,
                                  CeLoginJsonData& decodedJsonParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;

    const uint64_t sRootObjectTokenIdx = 0;

    uint64_t sResourceDumpIdx = 0;

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_ResourceDumps,
            strlen(JsonName_ResourceDumps), sResourceDumpIdx);
    }

    // Convert to CeLoginRc for consolidated RC handling
    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

    if (CeLoginRc::Success == sRc)
    {
        ServiceAuthority sIgnoredAuth;
        sRc = ParseCommonAcfFields(
            jsmnStateParm, decodedJsonParm.mExpirationDate, serialNumberParm,
            serialNumberLengthParm, sIgnoredAuth);
    }

    // Copy out resourcedump field
    if (CeLoginRc::Success == sRc)
    {
        JsmnUtils::JsmnString sResourceDumpStr =
            jsmnStateParm.getString(sResourceDumpIdx);
        sRc = CeLogin::base64Decode(sResourceDumpStr.mCharArray,
                                    sResourceDumpStr.mCharLength,
                                    decodedJsonParm.mAsciiScriptFile,
                                    sizeof(decodedJsonParm.mAsciiScriptFile),
                                    decodedJsonParm.mAsciiScriptFileLength);
    }

    return sRc;
}

CeLoginRc ParseBmcShellFields(const JsmnUtils::JsmnState& jsmnStateParm,
                              const AcfVersion versionParm,
                              const char* serialNumberParm,
                              const uint64_t serialNumberLengthParm,
                              CeLoginJsonData& decodedJsonParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;

    const uint64_t sRootObjectTokenIdx = 0;

    uint64_t sBmcShellIdx = 0;
    uint64_t sBmcTimeoutIdx = 0;
    uint64_t sIssueBmcDumpIdx = 0;

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_BmcShellScript,
            strlen(JsonName_BmcShellScript), sBmcShellIdx);
    }

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_BmcTimeoutVal,
            strlen(JsonName_BmcTimeoutVal), sBmcTimeoutIdx);
    }

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_IssueBmcDump,
            strlen(JsonName_IssueBmcDump), sIssueBmcDumpIdx);
    }

    // Convert to CeLoginRc for consolidated RC handling
    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

    if (CeLoginRc::Success == sRc)
    {
        ServiceAuthority sIgnoredAuth;
        sRc = ParseCommonAcfFields(
            jsmnStateParm, decodedJsonParm.mExpirationDate, serialNumberParm,
            serialNumberLengthParm, sIgnoredAuth);
    }

    // Copy out bmcshell field
    if (CeLoginRc::Success == sRc)
    {
        JsmnUtils::JsmnString sBmcShellStr =
            jsmnStateParm.getString(sBmcShellIdx);

        sRc = CeLogin::base64Decode(sBmcShellStr.mCharArray,
                                    sBmcShellStr.mCharLength,
                                    decodedJsonParm.mAsciiScriptFile,
                                    sizeof(decodedJsonParm.mAsciiScriptFile),
                                    decodedJsonParm.mAsciiScriptFileLength);
    }

    if (CeLoginRc::Success == sRc)
    {
        JsmnUtils::JsmnString sBmcTimeoutStr =
            jsmnStateParm.getString(sBmcTimeoutIdx);

        sRc = getUnsignedIntegerFromString(sBmcTimeoutStr.mCharArray,
                                           sBmcTimeoutStr.mCharLength,
                                           decodedJsonParm.mBmcTimeout);
    }

    if (CeLoginRc::Success == sRc)
    {
        JsmnUtils::JsmnString sIssueBmcDumpStr =
            jsmnStateParm.getString(sIssueBmcDumpIdx);
        const char* sDoIssueBmcDumpStr = "yes";
        decodedJsonParm.mIssueBmcDump =
            (0 == strncmp(sDoIssueBmcDumpStr, sIssueBmcDumpStr.mCharArray,
                          sIssueBmcDumpStr.mCharLength))
                ? true
                : false;
    }

    return sRc;
}

CeLoginRc ParseCommonAcfFields(const JsmnUtils::JsmnState& jsmnStateParm,
                               CeLogin_Date& dateParm,
                               const char* serialNumberParm,
                               const uint64_t serialNumberLengthParm,
                               ServiceAuthority& authorityParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    JsmnUtils::JsmnUtilRc sJsmnRc = JsmnUtils::Success;

    const uint64_t sRootObjectTokenIdx = 0;

    uint64_t sMachinesIdx = 0;
    uint64_t sExpirationIdx = 0;

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_Machines,
            strlen(JsonName_Machines), sMachinesIdx);
    }

    if (JsmnUtils::Success == sJsmnRc)
    {
        sJsmnRc = JsmnUtils::ObjectGetValueByKey(
            jsmnStateParm, sRootObjectTokenIdx, JsonName_Expiration,
            strlen(JsonName_Expiration), sExpirationIdx);
    }

    // Parsing complete, start using CeLogin return codes
    sRc = CeLoginRc(CeLoginRc::JsmnUtils, sJsmnRc);

    // verify machines
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseAuthorityFromMachineArrayToken(
            jsmnStateParm, sMachinesIdx, serialNumberParm,
            serialNumberLengthParm, authorityParm);
    }

    // get expiration date
    if (CeLoginRc::Success == sRc)
    {
        sRc = ParseDateFromToken(jsmnStateParm, sExpirationIdx, dateParm);
    }

    return sRc;
}