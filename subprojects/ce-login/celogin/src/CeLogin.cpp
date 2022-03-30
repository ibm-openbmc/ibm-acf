#include "CeLoginAsnV1.h"
#include "CeLoginJson.h"
#include "CeLoginUtil.h"

#include <CeLogin.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

namespace CeLogin
{
const char* AcfProcessingType = "P";
};

CeLogin::CeLoginRc
    CeLogin::isTimeExpired(CeLoginJsonData* jsonDataParm,
                           uint64_t& expirationTimeParm,
                           const uint64_t timeSinceUnixEpocInSecondsParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    ASN1_TIME* sAsn1UnixEpoch = ASN1_TIME_new();
    ASN1_TIME* sAsn1ExpirationTime = ASN1_TIME_new();
    if (!sAsn1ExpirationTime || !sAsn1UnixEpoch)
    {
        sRc = CeLoginRc::DetermineAuth_Asn1TimeAllocFailure;
    }
    else
    {
        ASN1_TIME* sResult = ASN1_TIME_set(sAsn1UnixEpoch, 0);
        if (sResult != sAsn1UnixEpoch)
        {
            sRc = CeLoginRc::DetermineAuth_GetAsn1UnixEpoch;
        }

        if (CeLoginRc::Success == sRc)
        {
            sRc =
                getAsn1Time(jsonDataParm->mExpirationDate, sAsn1ExpirationTime);
        }

        // Get the expiration time in seconds since unix epoch. Supports dates
        // up to 9999-12-31
        if (CeLoginRc::Success == sRc)
        {
            int sDay = 0;
            int sSec = 0;
            // ASN1_Time_diff returns 1 on success
            if (1 == ASN1_TIME_diff(&sDay, &sSec, sAsn1UnixEpoch,
                                    sAsn1ExpirationTime))
            {
                // If these numbers are negative this math fails
                if (sDay >= 0 && sSec >= 0)
                {
                    // Convert days to seconds and add remaining seconds
                    // Cast to uint64_t to prevent truncation
                    expirationTimeParm =
                        ((uint64_t)sDay * 24 * 60 * 60) + (uint64_t)sSec;
                }
                else
                {
                    sRc = CeLoginRc::
                        DetermineAuth_Asn1ExpirationToUnixOsslFailure;
                }
            }
            else
            {
                sRc = CeLoginRc::DetermineAuth_Asn1ExpirationToUnixFailure;
            }
        }

        if (CeLoginRc::Success == sRc)
        {
            if (timeSinceUnixEpocInSecondsParm > expirationTimeParm)
            {
                // The expiration date has passed
                sRc = CeLoginRc::AcfExpired;
            }
        }
    }

    if (sAsn1UnixEpoch)
        ASN1_TIME_free(sAsn1UnixEpoch);
    if (sAsn1ExpirationTime)
        ASN1_TIME_free(sAsn1ExpirationTime);
    return sRc;
}

CeLogin::CeLoginRc CeLogin::getServiceAuthorityV1(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const char* passwordParm,
    const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpocInSecondsParm, const uint8_t* publicKeyParm,
    const uint64_t publicKeyLengthParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm,
    CeLogin::ServiceAuthority& authorityParm, uint64_t& expirationTimeParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    authorityParm = CeLogin::ServiceAuth_None;
    uint8_t sGeneratedAuthCode[CeLogin_MaxHashedAuthCodeLength];

    CELoginSequenceV1* sDecodedAsn = NULL;
    CeLoginJsonData* sJsonData = NULL;

    if (!accessControlFileParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfPtr;
    }
    else if (0 == accessControlFileLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfLength;
    }
    else if (!passwordParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPasswordPtr;
    }
    else if (0 == passwordLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPasswordLength;
    }
    else if (!publicKeyParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyPtr;
    }
    else if (0 == publicKeyLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyLength;
    }
    else if (!serialNumberParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberPtr;
    }
    else if (0 == serialNumberLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberLength;
    }

    // Allocate on heap to avoid blowing the stack
    if (CeLoginRc::Success == sRc)
    {
        sJsonData = (CeLoginJsonData*)OPENSSL_malloc(sizeof(CeLoginJsonData));
        if (sJsonData)
        {
            memset(sJsonData, 0x00, sizeof(CeLoginJsonData));
        }
        else
        {
            sRc = CeLoginRc::JsonDataAllocationFailure;
        }
    }

    // Stack copy to store the parsed expiration time into. Only pass back
    // the value if the authority has validated as CE or Dev.
    uint64_t sExpirationTime = 0;

    if (CeLoginRc::Success == sRc)
    {
        // Returns a heap allocation of the decoded ANS1 structure.
        //  - Verify supported OID/signature algorithm
        //  - Verify expected ProcessingType
        //  - Verify signature over SourceFileData
        sRc = decodeAndVerifyAcf(accessControlFileParm,
                                 accessControlFileLengthParm, publicKeyParm,
                                 publicKeyLengthParm, sDecodedAsn);
    }

    // Verify system serial number is in machine list (and get the
    // authorization)
    if (CeLoginRc::Success == sRc)
    {
        sRc = decodeJson((const char*)sDecodedAsn->sourceFileData->data,
                         sDecodedAsn->sourceFileData->length, serialNumberParm,
                         serialNumberLengthParm, *sJsonData);
    }

    // Verify that the ACF has not expired (using UTC)
    if (CeLoginRc::Success == sRc)
    {
        sRc = isTimeExpired(sJsonData, sExpirationTime,
                            timeSinceUnixEpocInSecondsParm);
    }

    // Hash the provided ACF password
    if (CeLoginRc::Success == sRc)
    {
        sRc = createPasswordHash(
            passwordParm, passwordLengthParm, sJsonData->mAuthCodeSalt,
            sJsonData->mAuthCodeSaltLength, sJsonData->mIterations,
            sGeneratedAuthCode, sizeof(sGeneratedAuthCode),
            sJsonData->mHashedAuthCodeLength);
    }

    // Verify password hash matches the ACF hashed auth code
    if (CeLoginRc::Success == sRc)
    {
        if (0 != CRYPTO_memcmp(sGeneratedAuthCode, sJsonData->mHashedAuthCode,
                               sJsonData->mHashedAuthCodeLength))
        {
            sRc = CeLoginRc::PasswordNotValid;
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        authorityParm = sJsonData->mRequestedAuthority;
        expirationTimeParm = sExpirationTime;
    }

    if (sDecodedAsn)
        CELoginSequenceV1_free(sDecodedAsn);
    if (sJsonData)
        OPENSSL_free(sJsonData);

    return sRc;
}

CeLogin::CeLoginRc CeLogin::checkServiceAuthorityAcfIntegrityV1(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm,
    const uint64_t timeSinceUnixEpocInSecondsParm, const uint8_t* publicKeyParm,
    const uint64_t publicKeyLengthParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm, ServiceAuthority& authorityParm,
    uint64_t& expirationTimeParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    authorityParm = CeLogin::ServiceAuth_None;

    CELoginSequenceV1* sDecodedAsn = NULL;
    CeLoginJsonData* sJsonData = NULL;

    if (!accessControlFileParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfPtr;
    }
    else if (0 == accessControlFileLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidAcfLength;
    }
    else if (!publicKeyParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyPtr;
    }
    else if (0 == publicKeyLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidPublicKeyLength;
    }
    else if (!serialNumberParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberPtr;
    }
    else if (0 == serialNumberLengthParm)
    {
        sRc = CeLoginRc::GetSevAuth_InvalidSerialNumberLength;
    }

    // Allocate on heap to avoid blowing the stack
    if (CeLoginRc::Success == sRc)
    {
        sJsonData = (CeLoginJsonData*)OPENSSL_malloc(sizeof(CeLoginJsonData));
        if (sJsonData)
        {
            memset(sJsonData, 0x00, sizeof(CeLoginJsonData));
        }
        else
        {
            sRc = CeLoginRc::JsonDataAllocationFailure;
        }
    }

    // Stack copy to store the parsed expiration time into. Only pass back
    // the value if the authority has validated as CE or Dev.
    uint64_t sExpirationTime = 0;

    if (CeLoginRc::Success == sRc)
    {
        // Returns a heap allocation of the decoded ANS1 structure.
        //  - Verify supported OID/signature algorithm
        //  - Verify expected ProcessingType
        //  - Verify signature over SourceFileData
        sRc = decodeAndVerifyAcf(accessControlFileParm,
                                 accessControlFileLengthParm, publicKeyParm,
                                 publicKeyLengthParm, sDecodedAsn);
    }

    // Verify system serial number is in machine list (and get the
    // authorization)
    if (CeLoginRc::Success == sRc)
    {
        sRc = decodeJson((const char*)sDecodedAsn->sourceFileData->data,
                         sDecodedAsn->sourceFileData->length, serialNumberParm,
                         serialNumberLengthParm, *sJsonData);
    }

    // Verify that the ACF has not expired (using UTC)
    if (CeLoginRc::Success == sRc)
    {
        sRc = isTimeExpired(sJsonData, sExpirationTime,
                            timeSinceUnixEpocInSecondsParm);
    }

    if (CeLoginRc::Success == sRc)
    {
        authorityParm = sJsonData->mRequestedAuthority;
        expirationTimeParm = sExpirationTime;
    }

    if (sDecodedAsn)
        CELoginSequenceV1_free(sDecodedAsn);
    if (sJsonData)
        OPENSSL_free(sJsonData);

    return sRc;
}
