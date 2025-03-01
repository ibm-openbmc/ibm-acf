
#include <stdint.h>
#include <string.h>

#ifndef _CELOGIN_H
#define _CELOGIN_H

namespace CeLogin
{

extern const char* AcfProcessingType;

enum ServiceAuthority
{
    ServiceAuth_None = 0,
    ServiceAuth_User = 10, ///< Customer level
    ServiceAuth_CE = 20,   ///< CE/SSR level
    ServiceAuth_Dev = 30,  ///< Developer/Support level
};

enum AcfVersion
{
    CeLoginInvalidVersion = 0,
    CeLoginVersion1 = 1,
    CeLoginVersion2 = 2
};

enum
{
    CeLogin_PBKDF2_Iterations = 100000,
    AdminAuthCodeMaxLen = 256,
    MaxAsciiScriptFileLength = 1024,
};

enum AcfType
{
    AcfType_Invalid = 0,
    AcfType_Service = 1,
    AcfType_AdminReset = 2,
    AcfType_ResourceDump = 3,
    AcfType_BmcShell = 4,
};

struct CeLogin_Date
{
    uint16_t mYear;
    uint8_t mMonth;
    uint8_t mDay;
};

struct CeLoginRc
{
    enum Component
    {
        Base = 0,
        JsonUtils = 1, // Implementation Specific
        JsmnUtils = 2, // Implementation Specific

        // Must fit in 1 byte
    };

    enum RcBase
    {
        Success = 0x00,
        Failure = 0x01,
        UnsupportedVersion = 0x02,
        SignatureNotValid = 0x03,
        PasswordNotValid = 0x04,
        AcfExpired = 0x05,
        SerialNumberMismatch = 0x06,
        JsonDataAllocationFailure = 0x07,
        MissingReplayId = 0x08,
        UnsupportedAcfType = 0x09,
        InvalidReplayId = 0x0A,
        ReplayIdPersistenceFailure = 0x0B,
        PowerVMRequestedReplayFailure = 0x0C,

        CreateHsf_PasswordHashFailure = 0x13,
        CreateHsf_JsonHashFailure = 0x14,

        DecodeHsf_AsnDecodeFailure = 0x20,
        DecodeHsf_OidMismatchFailure = 0x21,
        DecodeHsf_CreateJsonDigestFailure = 0x22,
        DecodeHsf_PublicKeyAllocFailure = 0x23,
        DecodeHsf_PublicKeyImportFailure = 0x24,
        DecodeHsf_JsonParseFailure = 0x25,
        DecodeHsf_VersionMismatch = 0x26,
        DecodeHsf_ReadSerialNumberFailure = 0x27,
        DecodeHsf_ReadFrameworkEcFailure = 0x28,
        DecodeHsf_ReadMachineArrayFailure = 0x29,
        DecodeHsf_MachineArrayInvalidLength = 0x2A,
        DecodeHsf_ReadHashedAuthCodeFailure = 0x2B,
        DecodeHsf_ReadExpirationFailure = 0x2C,
        DecodeHsf_ReadRequestIdFailure = 0x2D,
        DecodeHsf_ReadSaltFailure = 0x2E,
        DecodeHsf_ReadIterationsFailure = 0x2F,

        VerifyAcf_AsnDecodeFailure = 0x30,
        VerifyAcf_OidMismatchFailure = 0x31,
        VerifyAcf_CreateJsonDigestFailure = 0x32,
        VerifyAcf_PublicKeyAllocFailure = 0x33,
        VerifyAcf_PublicKeyImportFailure = 0x34,
        VerifyAcf_InvalidParm = 0x35,
        VerifyAcf_Asn1CopyFailure = 0x36,
        VerifyAcf_Nid2OidFailed = 0x37,
        VerifyAcf_ProcessingTypeMismatch = 0x38,

        DetermineAuth_PasswordHashFailure = 0x40,
        DetermineAuth_Asn1TimeAllocFailure = 0x41,
        DetermineAuth_Asn1TimeFromUnixFailure = 0x42,
        DetermineAuth_AsnAllocFailure = 0x43,
        DetermineAuth_Asn1TimeCompareFailure = 0x44,
        DetermineAuth_GetAsn1UnixEpoch = 0x45,
        DetermineAuth_Asn1ExpirationToUnixFailure = 0x46,
        DetermineAuth_Asn1ExpirationToUnixOsslFailure = 0x47,

        Util_ValueFromJsonTagFailure = 0x50,

        HexToBin_HexPairOverflow = 0x60,
        HexToBin_InvalidHexString = 0x61,

        DateFromString_StrtoulFailure = 0x70,
        DateFromString_InvalidFormat = 0x71,
        DateFromString_InvalidParm = 0x72,

        GetAsn1Time_SetStringFailure = 0x80,
        GetAsn1Time_FormatStringFailure = 0x81,
        GetAsn1Time_InvalidParm = 0x82,

        CreatePasswordHash_InvalidInputBuffer = 0x90,
        CreatePasswordHash_InvalidInputBufferLength = 0x91,
        CreatePasswordHash_InvalidOutputBuffer = 0x92,
        CreatePasswordHash_InvalidOutputBufferLength = 0x93,
        CreatePasswordHash_OsslCallFailed = 0x94,
        CreatePasswordHash_InvalidInputSaltBuffer = 0x95,
        CreatePasswordHash_InvalidInputSaltLength = 0x96,
        CreatePasswordHash_ZeroIterations = 0x97,
        CreatePasswordHash_IterationTooLarge = 0x98,

        CreateDigest_InvalidInputBuffer = 0xA0,
        CreateDigest_InvalidInputBufferLength = 0xA1,
        CreateDigest_InvalidOutputBuffer = 0xA2,
        CreateDigest_InvalidOutputBufferLength = 0xA3,
        CreateDigest_OsslCallFailed = 0xA4,

        GetUnsignedIntFromString_InvalidBuffer = 0xB0,
        GetUnsignedIntFromString_ZeroLengthBuffer = 0xB1,
        GetUnsignedIntFromString_IntegerOverflow = 0xB2,
        GetUnsignedIntFromString_InvalidString = 0xB3,

        GetAuthFromFrameworkEc_InvalidParm = 0xC0,
        GetAuthFromFrameworkEc_InvalidFrameworkEc = 0xC1,

        GetSevAuth_InvalidAcfPtr = 0xD0,
        GetSevAuth_InvalidAcfLength = 0xD1,
        GetSevAuth_InvalidPasswordPtr = 0xD2,
        GetSevAuth_InvalidPasswordLength = 0xD3,
        GetSevAuth_InvalidPublicKeyPtr = 0xD4,
        GetSevAuth_InvalidPublicKeyLength = 0xD5,
        GetSevAuth_InvalidSerialNumberPtr = 0xD6,
        GetSevAuth_InvalidSerialNumberLength = 0xD7,

        // Must fit in 1-byte
    };

    inline CeLoginRc(const RcBase reasonParm) :
        mComponent(Base), mReason(reasonParm)
    {}

    inline CeLoginRc(const Component componentParm, const uint8_t reasonParm) :
        mComponent(0 == reasonParm ? 0 : componentParm), mReason(reasonParm)
    {}

    inline operator uint16_t() const
    {
        // Format manually to allow for consistant behavior on Big vs Little
        // Endian systems
        return (uint8_t)mComponent << 8 | (uint8_t)mReason;
    }

    inline bool isSuccess() const
    {
        return Success == (*this);
    }

    uint8_t mComponent;
    uint8_t mReason;
};

struct AcfUserFields
{
    AcfUserFields()
    {
        clear();
    }

    void clear()
    {
        mVersion = CeLoginInvalidVersion;
        mType = AcfType_Invalid;
        mExpirationTime = 0;
        memset(&mTypeSpecificFields, 0x00, sizeof(mTypeSpecificFields));
    }

    AcfVersion mVersion;
    AcfType mType;
    uint64_t mExpirationTime;

    union
    {
        struct
        {
            ServiceAuthority mAuth;
        } mServiceFields;

        struct
        {
            char mAdminAuthCode[AdminAuthCodeMaxLen];
            uint64_t mAdminAuthCodeLength;
        } mAdminResetFields;

        struct
        {
            char mResourceDump[MaxAsciiScriptFileLength];
            uint64_t mResourceDumpLength;
            ServiceAuthority mAuth;
        } mResourceDumpFields;

        struct
        {
            char mBmcShell[MaxAsciiScriptFileLength];
            uint64_t mBmcShellLength;
            uint64_t mBmcTimeout;
            bool mIssueBmcDump;
        } mBmcShellFields;

    } mTypeSpecificFields;
};

/// @note This function will return failure if called with a V2 ACF
CeLoginRc getServiceAuthorityV1(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const char* passwordParm,
    const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    ServiceAuthority& authorityParm, uint64_t& expirationTimeParm);

/// @note This function will return failure if called with a V2 ACF
CeLoginRc checkServiceAuthorityAcfIntegrityV1(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    ServiceAuthority& authorityParm, uint64_t& expirationTimeParm);

/** @brief Extract metadata from an ACF
 *
 *  This function validates a few ACF fields, but only those minimally required
 * to read certain metadata fields. Full validation of the ACF will need to use
 * the upload interface.
 *
 *  @param accessControlFileParm a pointer to the ASN1 encoded binary ACF
 *  @param accessControlFileLengthParm the byte length of the provided ACF
 *  @param timeSinceUnixEpochInSecondsParm the current system time encoded as a
 * unix timestamp
 *  @param publicKeyParm a pointer to the public key used to vaidate the
 * signature over the ACF
 *  @param publicKeyLengthParm the byte length of the provided public key
 *  @param serialNumberParm a pointer to the serial number of the current system
 *  @param serialNumberLengthParm the length of the provided serial number
 *  @param acfTypeParm the AcfType parsed from the provided file (e.g. service
 * or admin reset)
 *  @param expirationTimeParm the time at which this ACF expires
 *  @param expirationDateParm the formatted date at which this ACF expires
 *  @param versionParm the version field in the provided ACF
 *  @param hasReplayIdParm returns true if a replay ID is present in the ACF
 *
 *  @return A CeLoginRc indicating the result. CeLoginRc::Success indicates that
 * the ACF is valid and the output fields have been populated with the relevant
 * data from the file.
 */
CeLoginRc extractACFMetadataV2(const uint8_t* accessControlFileParm,
                               const uint64_t accessControlFileLengthParm,
                               const uint64_t timeSinceUnixEpochInSecondsParm,
                               const uint8_t* publicKeyParm,
                               const uint64_t publicKeyLengthParm,
                               const char* serialNumberParm,
                               const uint64_t serialNumberLengthParm,
                               AcfType& acfTypeParm,
                               uint64_t& expirationTimeParm,
                               CeLogin_Date& expirationDateParm,
                               AcfVersion& versionParm, bool& hasReplayIdParm);

#ifndef CELOGIN_POWERVM_TARGET

/** @brief Validate an ACF file at upload time
 *
 *  This function decodes and verifies several aspects of the provided ACF.
 *  This includes verifying the signature over the ACF, ensuring the ACF is not
 * expired, checking the serial number fields, and validating the replay ID, if
 * it exists. Upon successful validation, the output fields are udpated with the
 * values obtained from the ACF. THE CALLER MUST PERSIST THE RESULTING REPLAY ID
 * ON SUCCESS.
 *
 *  @param accessControlFileParm a pointer to the ASN1 encoded binary ACF
 *  @param accessControlFileLengthParm the byte length of the provided ACF
 *  @param timeSinceUnixEpochInSecondsParm the current system time encoded as a
 * unix timestamp
 *  @param publicKeyParm a pointer to the public key used to vaidate the
 * signature over the ACF
 *  @param publicKeyLengthParm the byte length of the provided public key
 *  @param serialNumberParm a pointer to the serial number of the current system
 *  @param serialNumberLengthParm the length of the provided serial number
 *  @param currentReplayIdParm the current replay ID persisted by the BMC. The
 * very first time this is called by a brand new system, the BMC may pass zero
 * as input.
 *  @param updatedReplayIdParm the value the BMC is required to persist as the
 * new replay ID if the function call succeeds. This must be passed in as the
 *                             currentReplayIdParm the next time this interface
 * is called.
 *  @param acfTypeParm the AcfType parsed from the provided file (e.g. service
 * or admin reset)
 *  @param expirationTimeParm the time at which this ACF expires
 *
 *  @return A CeLoginRc indicating the result. CeLoginRc::Success indicates that
 * the ACF is valid and the AcfUserFields has been populated with the relevant
 * fields from the file. On success, the updatedReplayIdParm must be persisted
 * and used on the next call to this interface.
 */
CeLoginRc verifyACFForBMCUploadV2(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, uint64_t& updatedReplayIdParm,
    AcfType& acfTypeParm, uint64_t& expirationTimeParm);

/** @brief Validate an ACF file and parse out the relevant fields
 *
 *  This function decodes and verifies several aspects of the provided ACF file.
 *  This includes verifying the signature over the ACF, ensuring the ACF is not
 * expired, checking the serial number fields, verifying the correct password
 * was entered (for a service ACF) and validating the replay ID was processed.
 * Upon successful validation, a AcfUserFields object is returned with the
 * fields relevant to the BMC. This interface assumes that the replay ID has
 * already been validated and persisted when the ACF was uploaded.
 *
 *  @param accessControlFileParm a pointer to the ASN1 encoded binary ACF
 *  @param accessControlFileLengthParm the byte length of the provided ACF
 *  @param passwordParm a pointer to the provided password
 *  @param passwordLengthParm the length of the provided password
 *  @param timeSinceUnixEpochInSecondsParm the current system time encoded as a
 * unix timestamp
 *  @param publicKeyParm a pointer to the public key used to vaidate the
 * signature over the ACF
 *  @param publicKeyLengthParm the byte length of the provided public key
 *  @param serialNumberParm a pointer to the serial number of the current system
 *  @param serialNumberLengthParm the length of the provided serial number
 *  @param currentReplayIdParm the current replay ID persisted by the BMC. Since
 * the replay ID is validated and stored at upload, this should always be equal
 *                             to the replay ID in the input ACF.
 *  @param userFieldsParm an instance of AcfUserFields which contains the data
 * parsed from the ACF on successful execution.
 *
 *  @return A CeLoginRc indicating the result. CeLoginRc::Success indicates that
 * the ACF is valid and the AcfUserFields has been populated with the relevant
 * fields.
 */
CeLoginRc checkAuthorizationAndGetAcfUserFieldsV2(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const char* passwordParm,
    const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, AcfUserFields& userFieldsParm);

#else

/** @brief PowerVM interface for checkAuthorizationAndGetAcfUserFieldsV2
 *
 *  The only difference here, is the presence of an output replay ID, which is
 * required on the PowerVM interface, but not on the analogous BMC interface.
 */
CeLoginRc checkAuthorizationAndGetAcfUserFieldsV2ForPowerVM(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const char* passwordParm,
    const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpochInSecondsParm,
    const uint8_t* publicKeyParm, const uint64_t publicKeyLengthParm,
    const char* serialNumberParm, const uint64_t serialNumberLengthParm,
    const uint64_t currentReplayIdParm, uint64_t& updatedReplayIdParm,
    const bool failValidationIfReplayIdPresentParm,
    AcfUserFields& userFieldsParm);

#endif /* CELOGIN_POWERVM_TARGET */

} // namespace CeLogin

#endif
