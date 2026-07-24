#include "CeLoginAsnV1.h"
#include "JsmnUtils.h"

#include <CeLogin.h> // CELOGIN_MLDSA_SUPPORTED
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#ifndef _CELOGINUTIL_H
#define _CELOGINUTIL_H

namespace CeLogin
{
extern const char* FrameworkEc_P10_Dev;
extern const char* FrameworkEc_P10_Service;
extern const char* FrameworkEc_P11_Dev;
extern const char* FrameworkEc_P11_Service;
extern const char* FrameworkEc_P12_Dev;
extern const char* FrameworkEc_P12_Service;

enum
{
    // The ACF, Digest, and DigestLength should use the same algorithms
    CeLogin_Acf_RSA_NID = NID_sha512WithRSAEncryption, // Used in ASN.1
    CeLogin_Digest_NID = NID_sha512, // Used for OpenSSL RSA sign/verify routine
    CeLogin_DigestLength = SHA512_DIGEST_LENGTH,

#ifdef CELOGIN_MLDSA_SUPPORTED
    // ML-DSA-87 (FIPS 204) signature algorithm OID stored in the ACF ASN.1
    // "algorithm" field. Unlike RSA, ML-DSA signs the message (the JSON
    // SourceFileData) directly rather than a pre-computed digest.
    CeLogin_Acf_MLDSA87_NID = NID_ML_DSA_87,
#endif

    CeLogin_MaxHashedAuthCodeLength = 256,
    CeLogin_MaxHashedAuthCodeSaltLength = 128,

    CeLogin_MaxNumberOfJsonTokens = 128, // somewhat arbitrary right now
};

CeLoginRc getCeLoginRcFromJsmnRc(const JsmnUtils::JsmnUtilRc jsmnRc);

CeLoginRc getBinaryFromHex(const char* hexStringParm,
                           const uint64_t hexStringLengthParm,
                           uint8_t* binaryParm, const uint64_t binarySizeParm,
                           uint64_t& binaryLengthParm);

CeLoginRc getDateFromString(const char* dateStringParm,
                            const uint64_t dateStringLengthParm,
                            CeLogin_Date& dateParm);

CeLoginRc getAsn1TimeForExpiration(const CeLogin_Date& dateParm,
                                   ASN1_TIME* timeParm);

CeLoginRc decodeAndVerifySignature(const uint8_t* accessControlFileParm,
                                   const uint64_t accessControlFileLengthParm,
                                   const uint8_t* publicKeyParm,
                                   uint64_t publicKeyLengthParm,
                                   CELoginSequenceV1*& decodedAsnParm);

CeLoginRc decodeAndVerifyAcf(const uint8_t* accessControlFileParm,
                             const uint64_t accessControlFileLengthParm,
                             const uint8_t* publicKeyParm,
                             uint64_t publicKeyLengthParm,
                             CELoginSequenceV1*& decodedAsnParm);

CeLoginRc createDigest(const uint8_t* inputDataParm,
                       const uint64_t inputDataLengthParm,
                       uint8_t* outputHashParm,
                       const uint64_t outputHashSizeParm);

CeLoginRc createPasswordHash(const char* inputDataParm,
                             const uint64_t inputDataLengthParm,
                             const uint8_t* inputSaltParm,
                             const uint64_t inputSaltLengthParm,
                             const uint64_t iterationsParm,
                             uint8_t* outputHashParm,
                             const uint64_t outputHashSizeParm,
                             const uint64_t requestedOutputLengthParm);

CeLoginRc getUnsignedIntegerFromString(const char* stringParm,
                                       const uint64_t stringLengthParm,
                                       uint64_t& integerParm);

CeLoginRc
    getServiceAuthorityFromFrameworkEc(const char* frameworkEcParm,
                                       const uint64_t frameworkEcLengthParm,
                                       ServiceAuthority& authParm);

/// @brief Generic wrapper for verifying a signature with OpenSSL
/// @param[in] publicKeyParm input public key to verify the signature with
/// @param[in] mdTypeParm message digest type
/// @param[in] signatureParm signature data to verify
/// @param[in] signatureLengthParm signature data length
/// @param[in] digestParm input digest
/// @param[in] digestLengthParm input digest length
/// @return CeLoginRc
CeLoginRc verifySignature(EVP_PKEY* publicKeyParm, const EVP_MD* mdTypeParm,
                          const uint8_t* signatureParm,
                          size_t signatureLengthParm, const uint8_t* digestParm,
                          size_t digestLengthParm);

/// @brief Generic wrapper for creating a signature with OpenSSL
/// @param[in] privateKeyParm input private key to create the signature with
/// @param[in] mdParm message digest type
/// @param[in] digestParm input digest
/// @param[in] digestParmLength length of input digest buffer
/// @param[out] generatedSignatureParm output signature buffer
/// @param[inout] signatureSizeParm input signature buffer size, output
/// generated signature size
/// @return CeLoginRc
CeLoginRc createSignature(EVP_PKEY* privateKeyParm, const EVP_MD* mdParm,
                          const uint8_t* digestParm, size_t digestParmLength,
                          uint8_t* generatedSignatureParm,
                          size_t& signatureSizeParm);

#ifdef CELOGIN_MLDSA_SUPPORTED
/// @brief Wrapper for creating an ML-DSA signature with OpenSSL. ML-DSA is not
/// a pre-hash scheme, so the full message is signed directly (no external
/// digest is computed).
/// @param[in] privateKeyParm input ML-DSA private key
/// @param[in] messageParm message (ACF SourceFileData JSON) to sign
/// @param[in] messageLengthParm length of the message
/// @param[out] generatedSignatureParm output signature buffer
/// @param[inout] signatureSizeParm input signature buffer size, output
/// generated signature size
/// @return CeLoginRc
CeLoginRc createSignatureMLDSA(EVP_PKEY* privateKeyParm,
                               const uint8_t* messageParm,
                               size_t messageLengthParm,
                               uint8_t* generatedSignatureParm,
                               size_t& signatureSizeParm);

/// @brief Wrapper for verifying an ML-DSA signature with OpenSSL. The signature
/// is verified over the full message (ACF SourceFileData JSON).
/// @param[in] publicKeyParm input ML-DSA public key
/// @param[in] signatureParm signature data to verify
/// @param[in] signatureLengthParm signature data length
/// @param[in] messageParm message the signature was generated over
/// @param[in] messageLengthParm length of the message
/// @return CeLoginRc
CeLoginRc verifySignatureMLDSA(EVP_PKEY* publicKeyParm,
                               const uint8_t* signatureParm,
                               size_t signatureLengthParm,
                               const uint8_t* messageParm,
                               size_t messageLengthParm);
#endif // CELOGIN_MLDSA_SUPPORTED

CeLoginRc base64Decode(const char* inputParm, const size_t inputLenParm,
                       uint8_t* decodedOutputParm,
                       const size_t decodedOutputLenParm,
                       size_t& numDecodedBytesParm);

}; // namespace CeLogin

#endif
