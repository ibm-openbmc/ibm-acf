
#include "CeLoginUtil.h"

#include "CeLoginJson.h"

#include <CeLogin.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>   // sprintf
#include <stdlib.h>  // strtoul
#include <string.h>  // strstr, memcpy, strlen
#include <strings.h> // bzero

#include <ce_logger.hpp>
/// TODO: rtc 268075 Determine if openssl can provide this function. If it can,
/// use that instead.
CeLogin::CeLoginRc CeLogin::getBinaryFromHex(const char* hexStringParm,
                                             const uint64_t hexStringLengthParm,
                                             uint8_t* binaryParm,
                                             const uint64_t binarySizeParm,
                                             uint64_t& binaryLengthParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    binaryLengthParm = 0;
    if (hexStringParm && binaryParm &&
        hexStringLengthParm <= (2 * binarySizeParm) &&
        0 == hexStringLengthParm % 2)
    {
        for (uint64_t sIdx = 0; sIdx < hexStringLengthParm; sIdx += 2)
        {
            char sByteHexString[3];
            memcpy(sByteHexString, &hexStringParm[sIdx], 2);
            sByteHexString[2] = '\0';
            unsigned long int sVal = strtoul(sByteHexString, NULL, 16);
            if (sVal <= 0xFF)
            {
                binaryParm[sIdx / 2] = sVal;
                binaryLengthParm++;
            }
            else
            {
                sRc = CeLoginRc::HexToBin_HexPairOverflow;
                break;
            }
        }
    }
    else
    {
        sRc = CeLoginRc::HexToBin_InvalidHexString;
    }
    return sRc;
}

CeLogin::CeLoginRc
    CeLogin::getDateFromString(const char* dateStringParm,
                               const uint64_t dateStringLengthParm,
                               CeLogin::CeLogin_Date& dateParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    if (dateStringParm && strlen("yyyy-mm-dd") == dateStringLengthParm)
    {
        if ('-' == dateStringParm[4] && '-' == dateStringParm[7])
        {
            char year[5];
            char month[3];
            char day[3];
            bzero(year, sizeof(year));
            bzero(month, sizeof(month));
            bzero(day, sizeof(day));

            memcpy(year, dateStringParm, 4);
            memcpy(month, dateStringParm + 5, 2);
            memcpy(day, dateStringParm + 8, 2);

            dateParm.mYear = strtoul(year, NULL, 10);
            dateParm.mMonth = strtoul(month, NULL, 10);
            dateParm.mDay = strtoul(day, NULL, 10);

            if (dateParm.mYear > 0 && dateParm.mMonth > 0 && dateParm.mDay > 0)
            {
                sRc = CeLoginRc::Success;
            }
            else
            {
                sRc = CeLoginRc::DateFromString_StrtoulFailure;
            }
        }
        else
        {
            sRc = CeLoginRc::DateFromString_InvalidFormat;
        }
    }
    else
    {
        sRc = CeLoginRc::DateFromString_InvalidParm;
    }

    return sRc;
}

CeLogin::CeLoginRc CeLogin::getAsn1Time(const CeLogin::CeLogin_Date& dateParm,
                                        ASN1_TIME* timeParm)
{
    // ASN1 Time Strings are in the form YYYYMMDDHHMMSSZ defined by RFC 5280
    // For example 20210113000102Z would be:
    // 01/13/2021 00:01:02 Zulu (i.e. GMT)
    CeLoginRc sRc = CeLoginRc::Success;

    if (timeParm)
    {
        char sTimeStr[16];

        const uint8_t sHour = 0;
        const uint8_t sMin = 0;
        const uint8_t sSec = 0;

        int sLength =
            sprintf(sTimeStr, "%04u%02u%02u%02u%02u%02uZ", dateParm.mYear,
                    dateParm.mMonth, dateParm.mDay, sHour, sMin, sSec);
        if (15 == sLength)
        {
            // returns 1 if the time value is successfully set and 0 otherwise
            if (1 != ASN1_TIME_set_string(timeParm, sTimeStr))
            {
                sRc = CeLoginRc::GetAsn1Time_SetStringFailure;
            }
        }
        else
        {
            sRc = CeLoginRc::GetAsn1Time_FormatStringFailure;
        }
    }
    else
    {
        sRc = CeLoginRc::GetAsn1Time_InvalidParm;
    }
    return sRc;
}

CeLogin::CeLoginRc CeLogin::decodeAndVerifyAcf(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const uint8_t* publicKeyParm,
    uint64_t publicKeyLengthParm, CeLogin::CELoginSequenceV1*& decodedAsnParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    EVP_PKEY* sPublicKey = NULL;
    uint8_t sHashReceivedJson[CeLogin_DigestLength];

    ASN1_OBJECT* sExpectedObject = NULL;

    if (!accessControlFileParm || !publicKeyParm)
    {
        sRc = CeLoginRc::VerifyAcf_InvalidParm;
    }

    if (CeLoginRc::Success == sRc)
    {
        // Validate the NID stored within the ASN.1 structure. This indicates
        // both the Digest algorithm and the Signature algorithm. It is
        // different from the NID provided to OpenSSL when performing the
        // sign/verify routine.

        // Returns pointer to a static definition of the object identifier.
        // Returns NULL on failure.
        sExpectedObject = OBJ_nid2obj(CeLogin_Acf_NID);
        if (!sExpectedObject)
        {
            CE_LOG_DEBUG("Failed to get NID");
            sRc = CeLoginRc::VerifyAcf_Nid2OidFailed;
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        // return a valid TYPE structure or NULL if an error occurs
        // NOTE: there is a "reuse" capability where an existing structure can
        // be provided,
        //       however in the event of a failure, the structure is
        //       automatically free'd. Either way there is undesirable behavior.
        //       So in this case returning a heap allocation seems slightly more
        //       straightforward.
        decodedAsnParm = d2i_CELoginSequenceV1(NULL, &accessControlFileParm,
                                               accessControlFileLengthParm);
        if (!decodedAsnParm)
        {

            CE_LOG_DEBUG("Failed to decode ASN.1 structure");
            sRc = CeLoginRc::VerifyAcf_AsnDecodeFailure;
        }
    }

    // Verify supported OID/signature algorithm
    if (CeLoginRc::Success == sRc)
    {
        // If the two are identical 0 is returned
        if (0 != OBJ_cmp(sExpectedObject, decodedAsnParm->algorithm->id))
        {
            sRc = CeLoginRc::VerifyAcf_OidMismatchFailure;
        }
    }

    // Verify expected ProcessingType
    if (CeLoginRc::Success == sRc)
    {
        const size_t sProcessingTypeLength = strlen(AcfProcessingType);
        if (sProcessingTypeLength !=
                (size_t)decodedAsnParm->processingType->length ||
            memcmp(AcfProcessingType, decodedAsnParm->processingType->data,
                   sProcessingTypeLength))
        {
            sRc = CeLoginRc::VerifyAcf_ProcessingTypeMismatch;
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        // returns a pointer to the hash value on success, NULL on failure
        // hash of the data, not the hash authcode
        sRc = createDigest(decodedAsnParm->sourceFileData->data,
                           decodedAsnParm->sourceFileData->length,
                           sHashReceivedJson, sizeof(sHashReceivedJson));
    }

    if (CeLoginRc::Success == sRc)
    {
        // return a valid EVP structure or NULL if an error occurs.
        sPublicKey = d2i_PUBKEY(NULL, &publicKeyParm, publicKeyLengthParm);
        if (!sPublicKey)
        {
            sRc = CeLoginRc::VerifyAcf_PublicKeyImportFailure;
        }
    }

    // Verify signature over SourceFileData
    if (CeLoginRc::Success == sRc)
    {
        sRc = verifySignature(sPublicKey, EVP_sha512(),
                              decodedAsnParm->signature->data,
                              decodedAsnParm->signature->length,
                              sHashReceivedJson, sizeof(sHashReceivedJson));
    }
    if (sPublicKey)
    {
        EVP_PKEY_free(sPublicKey);
    }

    return sRc;
}
CeLogin::CeLoginRc CeLogin::decodeAndVerifySignature(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const uint8_t* publicKeyParm,
    uint64_t publicKeyLengthParm, CeLogin::CELoginSequenceV1*& decodedAsnParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    EVP_PKEY* sPublicKey = NULL;
    uint8_t sHashReceivedJson[CeLogin_DigestLength];

    if (!accessControlFileParm || !publicKeyParm)
    {
        sRc = CeLoginRc::VerifyAcf_InvalidParm;
    }

    if (CeLoginRc::Success == sRc)
    {
        // return a valid TYPE structure or NULL if an error occurs
        // NOTE: there is a "reuse" capability where an existing structure can
        // be provided,
        //       however in the event of a failure, the structure is
        //       automatically free'd. Either way there is undesirable behavior.
        //       So in this case returning a heap allocation seems slightly more
        //       straightforward.
        decodedAsnParm = d2i_CELoginSequenceV1(NULL, &accessControlFileParm,
                                               accessControlFileLengthParm);
        if (!decodedAsnParm)
        {
            sRc = CeLoginRc::VerifyAcf_AsnDecodeFailure;
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        // returns a pointer to the hash value on success, NULL on failure
        // hash of the data, not the hash authcode
        sRc = createDigest(decodedAsnParm->sourceFileData->data,
                           decodedAsnParm->sourceFileData->length,
                           sHashReceivedJson, sizeof(sHashReceivedJson));
    }

    if (CeLoginRc::Success == sRc)
    {
        // return a valid EVP structure or NULL if an error occurs.
        sPublicKey = d2i_PUBKEY(NULL, &publicKeyParm, publicKeyLengthParm);
        if (!sPublicKey)
        {
            CE_LOG_DEBUG("Failed to import public key");
            sRc = CeLoginRc::VerifyAcf_PublicKeyImportFailure;
        }
    }

    // Verify signature over SourceFileData
    if (CeLoginRc::Success == sRc)
    {
        sRc = verifySignature(sPublicKey, EVP_sha512(),
                              decodedAsnParm->signature->data,
                              decodedAsnParm->signature->length,
                              sHashReceivedJson, sizeof(sHashReceivedJson));
    }

    if (sPublicKey)
    {
        EVP_PKEY_free(sPublicKey);
    }

    return sRc;
}
CeLogin::CeLoginRc CeLogin::createDigest(const uint8_t* inputDataParm,
                                         const uint64_t inputDataLengthParm,
                                         uint8_t* outputHashParm,
                                         const uint64_t outputHashSizeParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    if (!inputDataParm)
    {
        sRc = CeLoginRc::CreateDigest_InvalidInputBuffer;
    }
    else if (inputDataLengthParm <= 0)
    {
        sRc = CeLoginRc::CreateDigest_InvalidInputBufferLength;
    }
    else if (!outputHashParm)
    {
        sRc = CeLoginRc::CreateDigest_InvalidOutputBuffer;
    }
    else if (outputHashSizeParm < CeLogin_DigestLength)
    {
        sRc = CeLoginRc::CreateDigest_InvalidOutputBufferLength;
    }
    else
    {
        uint8_t* sHashResult =
            SHA512(inputDataParm, inputDataLengthParm, outputHashParm);

        if (outputHashParm != sHashResult)
        {
            sRc = CeLoginRc::CreateDigest_OsslCallFailed;
        }
    }
    return sRc;
}

CeLogin::CeLoginRc CeLogin::createPasswordHash(
    const char* inputDataParm, const uint64_t inputDataLengthParm,
    const uint8_t* inputSaltParm, const uint64_t inputSaltLengthParm,
    const uint64_t iterationsParm, uint8_t* outputHashParm,
    const uint64_t outputHashSizeParm, const uint64_t requestedOutputLengthParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    if (!inputDataParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidInputBuffer;
    }
    else if (0 == inputDataLengthParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidInputBufferLength;
    }
    else if (!inputSaltParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidInputSaltBuffer;
    }
    else if (0 == inputSaltLengthParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidInputSaltLength;
    }
    else if (!outputHashParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidOutputBuffer;
    }
    else if (0 == outputHashSizeParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidOutputBufferLength;
    }
    else if (outputHashSizeParm < requestedOutputLengthParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidOutputBufferLength;
    }
    else if (0 == requestedOutputLengthParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_InvalidOutputBufferLength;
    }
    else if (0 == iterationsParm)
    {
        sRc = CeLoginRc::CreatePasswordHash_ZeroIterations;
    }
    else if (iterationsParm > INT_MAX)
    {
        // Openssl takes the iteration as an int, any value larger than that
        // would get truncated.
        sRc = CeLoginRc::CreatePasswordHash_IterationTooLarge;
    }
    else
    {
        // return 1 on success or 0 on error.
        int sOsslRc =
            PKCS5_PBKDF2_HMAC(inputDataParm, inputDataLengthParm, inputSaltParm,
                              inputSaltLengthParm, iterationsParm, EVP_sha512(),
                              requestedOutputLengthParm, outputHashParm);

        if (1 != sOsslRc)
        {
            sRc = CeLoginRc::CreatePasswordHash_OsslCallFailed;
        }
    }
    return sRc;
}

CeLogin::CeLoginRc
    CeLogin::getUnsignedIntegerFromString(const char* stringParm,
                                          const uint64_t stringLengthParm,
                                          uint64_t& integerParm)
{
    const uint64_t sMaxLength = 10; // Well below the maximum value of a uint64
    CeLoginRc sRc = CeLoginRc::Success;

    if (!stringParm)
    {
        sRc = CeLoginRc::GetUnsignedIntFromString_InvalidBuffer;
    }
    else if (0 == stringLengthParm)
    {
        sRc = CeLoginRc::GetUnsignedIntFromString_ZeroLengthBuffer;
    }
    else if (stringLengthParm > sMaxLength)
    {
        sRc = CeLoginRc::GetUnsignedIntFromString_IntegerOverflow;
    }
    else
    {
        // Since strtoul will allow "extra" whitespace, sanitize the string to
        // make sure it conforms to an integer (and only an integer). Since we
        // want an unsigned integer we can also reject negative numbers.
        bool sIsValid = true;
        for (uint64_t sIdx = 0; sIdx < stringLengthParm && sIsValid; sIdx++)
        {
            sIsValid = (stringParm[sIdx] >= '0' && stringParm[sIdx] <= '9');
        }

        if (sIsValid)
        {
            char sNullTermString[sMaxLength + 1];
            memset(sNullTermString, 0, sizeof(sNullTermString));
            memcpy(sNullTermString, stringParm, stringLengthParm);
            integerParm = strtoul(sNullTermString, NULL, 10);
        }
        else
        {
            sRc = CeLoginRc::GetUnsignedIntFromString_InvalidString;
        }
    }
    return sRc;
}

CeLogin::CeLoginRc CeLogin::getServiceAuthorityFromFrameworkEc(
    const char* frameworkEcParm, const uint64_t frameworkEcLengthParm,
    ServiceAuthority& authParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    authParm = ServiceAuth_None;

    if (!frameworkEcParm || 0 == frameworkEcLengthParm)
    {
        sRc = CeLoginRc::GetAuthFromFrameworkEc_InvalidParm;
    }
    else
    {
        if (frameworkEcLengthParm == strlen(FrameworkEc_P10_Dev) &&
            0 == memcmp(frameworkEcParm, FrameworkEc_P10_Dev,
                        frameworkEcLengthParm))
        {
            authParm = ServiceAuth_Dev;
        }
        else if (frameworkEcLengthParm == strlen(FrameworkEc_P10_Service) &&
                 0 == memcmp(frameworkEcParm, FrameworkEc_P10_Service,
                             frameworkEcLengthParm))
        {
            authParm = ServiceAuth_CE;
        }
        else if (frameworkEcLengthParm == strlen(FrameworkEc_P11_Dev) &&
                 0 == memcmp(frameworkEcParm, FrameworkEc_P11_Dev,
                             frameworkEcLengthParm))
        {
            authParm = ServiceAuth_Dev;
        }
        else if (frameworkEcLengthParm == strlen(FrameworkEc_P11_Service) &&
                 0 == memcmp(frameworkEcParm, FrameworkEc_P11_Service,
                             frameworkEcLengthParm))
        {
            authParm = ServiceAuth_CE;
        }
        else
        {
            sRc = CeLoginRc::GetAuthFromFrameworkEc_InvalidFrameworkEc;
        }
    }
    return sRc;
}

CeLogin::CeLoginRc CeLogin::createSignature(EVP_PKEY* privateKeyParm,
                                            const EVP_MD* mdParm,
                                            const uint8_t* digestParm,
                                            size_t digestParmSize,
                                            uint8_t* generatedSignatureParm,
                                            size_t& signatureSizeParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    EVP_PKEY_CTX* sCtx = EVP_PKEY_CTX_new(privateKeyParm, NULL);
    int sResult = 1;
    if (!sCtx)
    {
        sResult = 0;
    }
    if (1 == sResult)
    {
        sResult = EVP_PKEY_sign_init(sCtx);
    }
    if (1 == sResult)
    {
        sResult = EVP_PKEY_CTX_set_rsa_padding(sCtx, RSA_PKCS1_PADDING);
    }
    if (1 == sResult)
    {
        sResult = EVP_PKEY_CTX_set_signature_md(sCtx, mdParm);
    }
    if (1 == sResult)
    {
        // This call calculates the final signature length
        size_t sCalculatedSignatureSize = 0;
        sResult = EVP_PKEY_sign(sCtx, NULL, &sCalculatedSignatureSize,
                                digestParm, digestParmSize);
        if ((1 == sResult) && (sCalculatedSignatureSize == signatureSizeParm))
        {
            // This call creates the signature
            sResult =
                EVP_PKEY_sign(sCtx, generatedSignatureParm, &signatureSizeParm,
                              digestParm, digestParmSize);
        }
        else
        {
            sResult = 0;
        }
    }
    if (1 != sResult)
    {
        sRc = CeLoginRc::Failure;
    }
    if (sCtx)
    {
        EVP_PKEY_CTX_free(sCtx);
    }
    return sRc;
}

CeLogin::CeLoginRc CeLogin::verifySignature(EVP_PKEY* publicKeyParm,
                                            const EVP_MD* mdTypeParm,
                                            const uint8_t* signatureParm,
                                            size_t signatureLengthParm,
                                            const uint8_t* digestParm,
                                            size_t digestLengthParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    int sVerifyResult = 1;
    EVP_PKEY_CTX* sCtx = EVP_PKEY_CTX_new(publicKeyParm, NULL /* no engine */);
    if (!sCtx)
    {
        sVerifyResult = 0;
    }
    if (1 == sVerifyResult)
    {
        sVerifyResult = EVP_PKEY_verify_init(sCtx);
    }
    if (1 == sVerifyResult)
    {
        sVerifyResult = EVP_PKEY_CTX_set_rsa_padding(sCtx, RSA_PKCS1_PADDING);
    }
    if (1 == sVerifyResult)
    {
        sVerifyResult = EVP_PKEY_CTX_set_signature_md(sCtx, mdTypeParm);
    }
    if (1 == sVerifyResult)
    {
        sVerifyResult =
            EVP_PKEY_verify(sCtx, signatureParm, signatureLengthParm,
                            digestParm, digestLengthParm);
    }
    if (1 != sVerifyResult)
    {
        sRc = CeLoginRc::SignatureNotValid;
    }
    if (sCtx)
    {
        EVP_PKEY_CTX_free(sCtx);
    }
    return sRc;
}

CeLogin::CeLoginRc CeLogin::base64Decode(const char* inputParm,
                                         const size_t inputLenParm,
                                         uint8_t* decodedOutputParm,
                                         const size_t decodedOutputLenParm,
                                         size_t& numDecodedBytesParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    // Find expected length of decoded binary output, must be divisible by 4
    const size_t sExpectedOutputLen = (inputLenParm / 4) * 3;

    // Check for bad input parameters. Require sufficient space in
    // decodedOutputParm to handle any padding.
    if (sExpectedOutputLen > decodedOutputLenParm || 0 != inputLenParm % 4 ||
        NULL == inputParm || NULL == decodedOutputParm)
    {
        // Output buffer length should not be less than what is required for
        // decode Input length should be divisible by 4
        sRc = CeLoginRc::Failure;
    }
    else
    {
        const size_t sNumBytesDecoded = EVP_DecodeBlock(
            decodedOutputParm, (unsigned char*)inputParm, inputLenParm);
        if (sNumBytesDecoded != sExpectedOutputLen)
        {
            // Unexpected error, number of decoded bytes should match what is
            // expected
            sRc = CeLoginRc::Failure;
        }
        else
        {
            // Determine the number of "extra" bytes due to padding. There can
            // be at most two "=", 1 "=" indicates one extra byte of data 2 "="
            // indicates two extra bytes of data
            if ('=' == inputParm[inputLenParm - 2])
            {
                numDecodedBytesParm = sNumBytesDecoded - 2;
            }
            else if ('=' == inputParm[inputLenParm - 1])
            {
                numDecodedBytesParm = sNumBytesDecoded - 1;
            }
            else
            {
                numDecodedBytesParm = sNumBytesDecoded;
            }
        }
    }

    return sRc;
}