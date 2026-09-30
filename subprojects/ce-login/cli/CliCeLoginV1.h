
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

enum SignatureAlgorithm
{
    // sha512WithRSAEncryption - legacy/default. Signs a SHA-512 digest of the
    // JSON payload.
    SignatureAlgorithm_RsaSha512,
    // id-ml-dsa-87 (FIPS 204). Signs the JSON payload message directly.
    SignatureAlgorithm_MlDsa87,
};

enum
{
    // Working buffer used while DER-encoding the ACF. Must be large enough for
    // the largest supported signature: an ML-DSA-87 signature is 4627 bytes
    // plus the JSON payload and ASN.1 framing, which exceeds the legacy
    // 4096-byte RSA sizing.
    CeLogin_MaxAsn1AcfSize = 16384,

    // Largest JSON payload the production signing server will accept.
    //
    // Pure ML-DSA signs the message itself rather than a digest, so the entire
    // ACF payload has to cross the signing interface. RSA is unaffected: it
    // signs a 64-byte SHA-512 digest no matter how large the payload is.
    //
    // The payload is currently bounded well below this by
    // MaxAsciiScriptFileLength and CeLogin_MaxNumberOfJsonTokens, but neither
    // was chosen with this limit in mind. Raising either one can push the
    // payload past it, which is why the check exists rather than relying on
    // those caps to hold.
    //
    // Raise this only when the signing server's own limit is raised. Removing
    // the constraint outright requires ExternalMu-ML-DSA, which submits a fixed
    // 64-byte message representative in place of the payload.
    CeLogin_MaxMlDsaSigningPayloadSize = 3072,
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
    SignatureAlgorithm mSignatureAlgorithm = SignatureAlgorithm_RsaSha512;
};

// Maps a signature algorithm to the ASN.1 OID NID written into the ACF.
int getNidForSignatureAlgorithm(SignatureAlgorithm algorithmParm);

// Detects the signature algorithm implied by a private/public key encoded in
// DER. Returns true on a recognized key type (RSA or ML-DSA-87).
bool detectSignatureAlgorithm(const std::vector<uint8_t>& keyParm,
                              SignatureAlgorithm& algorithmParm);

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

CeLoginRc createCeLoginAcfV1Payload(const CeLoginCreateHsfArgsV1& argsParm,
                                    std::string& generatedAcfParm);

// SHA-512 digest over the JSON payload. This is what gets signed for RSA; it is
// exposed so the production flow can hand it to an external signer.
CeLoginRc
    createCeLoginAcfPayloadDigest(const std::string& jsonParm,
                                  std::vector<uint8_t>& generatedDigestParm);

// Signs the JSON payload using argsParm.mSignatureAlgorithm. RSA signs a
// SHA-512 digest of the payload (computed internally); ML-DSA signs the payload
// directly.
CeLoginRc
    createCeLoginAcfV1Signature(const CeLoginCreateHsfArgsV1& argsParm,
                                const std::string& jsonParm,
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
