#include "CeLoginCli.h"
#include "CliCeLoginV2.h"
#include "CliUtils.h"
#include "CliTypes.h"

#include <CeLogin.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using CeLogin::CeLoginRc;

using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace CreateProductionV2
{
    enum ProdConstants
    {
        Prod_DigestByteLength = 512 / 8,
        Prod_SaltByteLength   = 512 / 8,
        Prod_PasswordLength   = 10,
    };

    struct Arguments
    {
        vector<cli::Machine>    mMachines;
        string                  mExpirationDate;
        string                  mPasswordFile;
        string                  mComment;
        string                  mOutputFile;
        string                  mJsonPath;
        string                  mSignaturePath;
        string                  mJsonDigestPath;
        string                  mType;
        bool                    mNoReplayId;
        bool                    mVerbose;
        bool                    mHelp;

        Arguments()
        : mNoReplayId(false)
        , mVerbose(false)
        , mHelp(false)

        {
        }
    };

    enum OptOptions
    {
        Machine,
        ExpirationDate,
        PasswordFile,
        Comment,
        OutputFile,
        JsonPath,
        JsonSignaturePath,
        JsonDigestPath,
        AcfType,
        NoReplayId,
        Verbose,
        Help,
        NOptOptions
    };

    struct option long_options[NOptOptions + 1] = {
        {"machine", required_argument, NULL, 'm'},
        {"expirationDate", required_argument, NULL, 'e'},
        {"password", required_argument, NULL, 'p'},
        {"Comment", required_argument, NULL, 'c'},
        {"acf", required_argument, NULL, 'o'},
        {"json", required_argument, NULL, 'j'},
        {"signature", required_argument, NULL, 's'},
        {"digest", required_argument, NULL, 'd'},
        {"type", required_argument, NULL, 't'},
        {"noReplayId", no_argument, NULL, 'n'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}};

    string options_description[NOptOptions] = {
        "<processor gen (P10,P11)>,<authority (dev,ce)>,<7-char serial number|UNSET>",
        "ACF expiration date in the format: \"YYYY-MM-DD\"",
        "Path/file to write generated password into",
        "Comment to embed in ACF asn1. Written into the \"SourceFileName\" field",
        "Path/file to write the ACF binary into",
        "Path/file to write the JSON structure into",
        "Path/file to read the signature over the JSON's digest",
        "Path/file to write the digest over the JSON into",
        "<service,adminreset>",
        "Exclude the replay ID from the ACF",
        "Help",
        "Verbose"};

    const std::string paragraph_description =
        "General Flow: create json & digest, create signature, package json & signature into ACF\n"
        "\t1. celogin_cli create_prod\n"
        "\t\t-m <machine> [-m <machine> -m ...]\n"
        "\t\t-e <YYYY-MM-DD>\n"
        "\t\t-j <json-out-file>\n"
        "\t\t-p <password-out-file>\n"
        "\t\t[-d <digest-out-file>]\n"
        "\t2. (environment specific step to generate signature over digest)\n"
        "\t3. celogin_cli create_prod\n"
        "\t\t-j <json-file>\n"
        "\t\t-s <signature-file>\n"
        "\t\t-o <output-acf-file>\n"
        "\t\t-c <Comment>\n";

    enum Operation
    {
        Operation_Invalid,
        CreateJsonAndDigest,
        PackageJsonAndSignature,
    };

    void parseArgs(int argc, char** argv, struct Arguments& args)
    {
        string short_options = "";

        for (int i = 0; i < NOptOptions; i++)
        {
            short_options += long_options[i].val;
            if (required_argument == long_options[i].has_arg)
            {
                short_options += ":";
            }
        }

        int c;
        while (1)
        {
            int option_index = 0;
            c = getopt_long(argc, argv, short_options.c_str(), long_options,
                            &option_index);
            if (c == -1)
                break;
            else if (c == long_options[Machine].val)
            {
                // Expected format: <processor gen>,<authority>,<serial number>
                // Example: P10,Dev,12345
                string sArg = optarg;
                // Count the number of delimiters, should be 2
                cli::Machine sMachine;
                if (cli::parseMachineFromString(sArg, sMachine))
                {
                    args.mMachines.push_back(sMachine);
                }
                else
                {
                    cout << "ERROR: Unexpected string for machine type: \"" << sArg
                        << "\"" << endl;
                }
            }
            else if (c == long_options[ExpirationDate].val)
            {
                args.mExpirationDate = optarg;
            }
            else if (c == long_options[PasswordFile].val)
            {
                args.mPasswordFile = optarg;
            }
            else if (c == long_options[Comment].val)
            {
                args.mComment = optarg;
            }
            else if (c == long_options[OutputFile].val)
            {
                args.mOutputFile = optarg;
            }
            else if (c == long_options[JsonPath].val)
            {
                args.mJsonPath = optarg;
            }
            else if (c == long_options[JsonSignaturePath].val)
            {
                args.mSignaturePath = optarg;
            }
            else if (c == long_options[JsonDigestPath].val)
            {
                args.mJsonDigestPath = optarg;
            }
            else if (c == long_options[AcfType].val)
            {
                args.mType = optarg;
            }
            else if (c == long_options[NoReplayId].val)
            {
                args.mNoReplayId = true;
            }
            else if (c == long_options[Help].val)
            {
                args.mHelp = true;
            }
            else if (c == long_options[Verbose].val)
            {
                args.mVerbose = true;
            }
        }
    }

    bool validateArgs(const Arguments& args, Operation& operationParm, CeLogin::AcfType& acfTypeParm)
    {
        bool sIsValidArgs = false;

        operationParm = Operation_Invalid;
        acfTypeParm = CeLogin::AcfType_Service;

        // Check on each of the operations

        const bool sIsMachine = !args.mMachines.empty();
        const bool sIsExpiration = !args.mExpirationDate.empty();
        const bool sIsComment = !args.mComment.empty();
        const bool sIsPassword = !args.mPasswordFile.empty();
        const bool sIsJson = !args.mJsonPath.empty();
        const bool sIsDigest = !args.mJsonDigestPath.empty();
        const bool sIsSignature = !args.mSignaturePath.empty();
        const bool sIsAcf = !args.mOutputFile.empty();
        const bool sNoReplayId = args.mNoReplayId;

        if (sIsMachine && sIsExpiration && !sIsComment && sIsPassword &&
            sIsJson /* && sIsDigest */ && !sIsSignature && !sIsAcf)
        {
            sIsValidArgs = true;
            operationParm = CreateJsonAndDigest;
        }
        else if (!sIsMachine && !sIsExpiration /* && sIsComment */ &&
                !sIsPassword && sIsJson && !sIsDigest && sIsSignature && sIsAcf)
        {
            sIsValidArgs = true;
            operationParm = PackageJsonAndSignature;
        }
        else
        {
            cerr << "Unknown combination of args" << endl;
        }
        
        if(sIsValidArgs)
        {
            const bool sIsServiceType = args.mType == "service";       
            const bool sIsAdminResetType = args.mType == "adminreset";

            if(sIsServiceType) { acfTypeParm = CeLogin::AcfType_Service; }
            else if(sIsAdminResetType) { acfTypeParm = CeLogin::AcfType_AdminReset; }
            else
            {
                sIsValidArgs = false;
                if(args.mType.empty()) {
                    cerr << "Must specify ACF type" << endl;
                }
                else {
                    cerr << "Unknown type: " << args.mType << endl;
                }
            }

            if(sIsValidArgs && CeLogin::AcfType_AdminReset == acfTypeParm)
            {
                if(sNoReplayId)
                {
#ifndef TOLERATE_ADMIN_RESET_REPLAY
                    sIsValidArgs = false;
                    cerr << "Admin reset requires replay ID" << endl;
#endif
                }
            }
        }

        return sIsValidArgs;
    }
}; // namespace CreateProductionV2

using namespace CreateProductionV2;

using CeLogin::CeLoginCreateHsfArgsV1;
using CeLogin::CeLoginCreateHsfArgsV2;

CeLoginRc cli::createProductionHsfV2(int argc, char** argv)
{
    CeLoginRc sRc = CeLoginRc::Success;

    Arguments sArgs;
    parseArgs(argc - 1, argv + 1, sArgs);

    Operation sOperation = Operation_Invalid;
    CeLogin::AcfType sAcfType = CeLogin::AcfType_Service;

    CeLoginCreateHsfArgsV2 sCreateHsfArgsV2;
    CeLoginCreateHsfArgsV1& sCreateHsfArgsV1 = sCreateHsfArgsV2.mV1Args;

    if (sArgs.mHelp)
    {
        cli::printHelp(argv[0], argv[1], paragraph_description, long_options,
                       options_description, NOptOptions);
        sRc = CeLoginRc::Success;
    }
    else if (!validateArgs(sArgs, sOperation, sAcfType))
    {
        // validateArgs prints error messages
        sRc = CeLoginRc::Failure;
    }
    else if (sOperation == CreateJsonAndDigest)
    {
        string sJson;
        vector<uint8_t> sHash;
        // JSW TODO pass the int along instead?
        //const bool sIsAdminReset = ("adminreset" == sArgs.mType);

        char* sPasswordPtr = (char*)OPENSSL_secure_zalloc(Prod_PasswordLength +
                                                          1); // +1 for '\0'
        if (!sPasswordPtr)
        {
            sRc = CeLoginRc::Failure;
        }

        if (CeLoginRc::Success == sRc)
        {
            sRc = CeLogin::generateRandomPassword(sPasswordPtr,
                                                  Prod_PasswordLength);
        }

        if (CeLoginRc::Success == sRc)
        {
            sRc = CeLogin::getLocalRequestId(sCreateHsfArgsV1.mRequestId);
        }

        if (CeLoginRc::Success == sRc)
        {
            sCreateHsfArgsV1.mMachines = sArgs.mMachines;

            sCreateHsfArgsV1.mPasswordPtr = sPasswordPtr;
            sCreateHsfArgsV1.mPasswordLength = Prod_PasswordLength;
            sCreateHsfArgsV1.mExpirationDate = sArgs.mExpirationDate;

            // 512 bit digest & salt
            sCreateHsfArgsV1.mHashedAuthCodeLength = Prod_DigestByteLength;
            sCreateHsfArgsV1.mSaltLength = Prod_SaltByteLength;
            sCreateHsfArgsV1.mIterations = CeLogin::CeLogin_PBKDF2_Iterations;
            sCreateHsfArgsV1.mPasswordHashAlgorithm = CeLogin::PasswordHash_Production;

            sCreateHsfArgsV2.mType = sArgs.mType;
            sCreateHsfArgsV2.mNoReplayId = sArgs.mNoReplayId;

            sRc = CeLogin::createCeLoginAcfV2Payload(sCreateHsfArgsV2, sJson, sHash);
        }

        if (CeLoginRc::Success == sRc)
        {
            if (writeBinaryFile(sArgs.mJsonPath, (const uint8_t*)sJson.data(),
                                sJson.length()))
            {
                cout << "Wrote: " << sArgs.mJsonPath << endl;
            }
            else
            {
                cout << "Error writing json file" << endl;
                sRc = CeLoginRc::Failure;
            }

            // Digest Output is not required
            if (!sArgs.mJsonDigestPath.empty())
            {
                if (writeBinaryFile(sArgs.mJsonDigestPath,
                                    (const uint8_t*)sHash.data(), sHash.size()))
                {
                    cout << "Wrote: " << sArgs.mJsonDigestPath << endl;
                }
                else
                {
                    cout << "Error writing digest file " << endl;
                    sRc = CeLoginRc::Failure;
                }
            }

            if (writeBinaryFile(sArgs.mPasswordFile,
                                (const uint8_t*)sCreateHsfArgsV1.mPasswordPtr,
                                sCreateHsfArgsV1.mPasswordLength))
            {
                cout << "Wrote: " << sArgs.mPasswordFile << endl;
            }
            else
            {
                cout << "Error writing generated password file" << endl;
                sRc = CeLoginRc::Failure;
            }
        }

        if (sPasswordPtr)
        {
            OPENSSL_secure_clear_free(sPasswordPtr, Prod_PasswordLength);
        }
    }
    else if (sOperation == PackageJsonAndSignature)
    {
        std::vector<uint8_t> sJson;
        std::vector<uint8_t> sSignature;
        std::vector<uint8_t> sAcf;

        sCreateHsfArgsV1.mSourceFileName = sArgs.mComment.empty() ? "" : sArgs.mComment;

        if(!readBinaryFile(sArgs.mJsonPath, sJson))
        {
            cerr << "Error reading json file" << endl;
            sRc = CeLoginRc::Failure;
        }
        else if(!readBinaryFile(sArgs.mSignaturePath, sSignature))
        {
            cerr << "Error reading signature" << endl;
            sRc = CeLoginRc::Failure;
        }
        else
        {
            // Both Json and Signature files have been read
            string sJsonStr = string((char*)sJson.data(), (char*)sJson.data() + sJson.size());
            sRc = CeLogin::createCeLoginAcfV2Asn1(sCreateHsfArgsV2, sJsonStr, sSignature, sAcf);
        }

        if(CeLoginRc::Success == sRc)
        {
            if(writeBinaryFile(sArgs.mOutputFile, (const uint8_t*)sAcf.data(), sAcf.size()))
            {
                cout << "Wrote: " << sArgs.mOutputFile << endl;
            }
            else
            {
                cout << "Error writing final ACF file" << endl;
                sRc = CeLoginRc::Failure;
            }
        }
    }
    else
    {
        cout << "Unknown subcommand option" << endl;
        sRc = CeLoginRc::Failure;
    }

    cout << "RC: " << std::hex << (int)sRc << endl;
    return sRc;
}
