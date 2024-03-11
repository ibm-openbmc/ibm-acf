#include "CeLoginCli.h"
#include "CliCeLoginV1.h"
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

using namespace std;

namespace CreateProduction
{
enum ProdConstants
{
    Prod_DigestByteLength = 512 / 8,
    Prod_SaltByteLength = 512 / 8,
    Prod_PasswordLength = 10,
};

struct Arguments
{
    vector<cli::Machine> mMachines;
    string mExpirationDate;
    string mPasswordFile;
    string mComment;
    string mOutputFile;
    string mJsonPath;
    string mSignaturePath;
    string mJsonDigestPath;
    bool mVerbose;
    bool mHelp;
    Arguments() : mVerbose(false), mHelp(false)

    {}
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

bool validateArgs(const Arguments& args, Operation& operationParm)
{
    bool sIsValidArgs = false;

    // Check on each of the operations

    bool mIsMachine = !args.mMachines.empty();
    bool mIsExpiration = !args.mExpirationDate.empty();
    bool mIsComment = !args.mComment.empty();
    bool mIsPassword = !args.mPasswordFile.empty();
    bool mIsJson = !args.mJsonPath.empty();
    bool mIsDigest = !args.mJsonDigestPath.empty();
    bool mIsSignature = !args.mSignaturePath.empty();
    bool mIsAcf = !args.mOutputFile.empty();

    if (mIsMachine && mIsExpiration && !mIsComment && mIsPassword &&
        mIsJson /* && mIsDigest */ && !mIsSignature && !mIsAcf)
    {
        sIsValidArgs = true;
        operationParm = CreateJsonAndDigest;
    }
    else if (!mIsMachine && !mIsExpiration /* && mIsComment */ &&
             !mIsPassword && mIsJson && !mIsDigest && mIsSignature && mIsAcf)
    {
        sIsValidArgs = true;
        operationParm = PackageJsonAndSignature;
    }
    else
    {
        cout << "Unknown combination of args" << endl;
    }

    return sIsValidArgs;
}

}; // namespace CreateProduction

using namespace CreateProduction;

CeLogin::CeLoginRc cli::createProductionHsf(int argc, char** argv)
{
    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Success;

    Arguments sArgs;
    parseArgs(argc - 1, argv + 1, sArgs);

    Operation sOperation = Operation_Invalid;

    if (sArgs.mHelp)
    {
        cli::printHelp(argv[0], argv[1], paragraph_description, long_options,
                       options_description, NOptOptions);
        sRc = CeLogin::CeLoginRc::Success;
    }
    else if (!validateArgs(sArgs, sOperation))
    {
        // validateArgs prints error messages
        sRc = CeLogin::CeLoginRc::Failure;
    }
    else if (sOperation == CreateJsonAndDigest)
    {
        string sJson;
        vector<uint8_t> sHash;

        CeLogin::CeLoginCreateHsfArgsV1 sCreateHsfArgs;

        sCreateHsfArgs.mMachines = sArgs.mMachines;

        char* sPasswordPtr = (char*)OPENSSL_secure_zalloc(Prod_PasswordLength +
                                                          1); // +1 for '\0'
        if (!sPasswordPtr)
        {
            // error
            sRc = CeLogin::CeLoginRc::Failure;
        }

        if (CeLogin::CeLoginRc::Success == sRc)
        {
            sRc = CeLogin::generateRandomPassword(sPasswordPtr,
                                                  Prod_PasswordLength);
        }

        if (CeLogin::CeLoginRc::Success == sRc)
        {
            sRc = CeLogin::getLocalRequestId(sCreateHsfArgs.mRequestId);
        }

        if (CeLogin::CeLoginRc::Success == sRc)
        {
            sCreateHsfArgs.mPasswordPtr = sPasswordPtr;
            sCreateHsfArgs.mPasswordLength = Prod_PasswordLength;
            sCreateHsfArgs.mExpirationDate = sArgs.mExpirationDate;

            // 512 bit digest & salt
            sCreateHsfArgs.mHashedAuthCodeLength = Prod_DigestByteLength;
            sCreateHsfArgs.mSaltLength = Prod_SaltByteLength;
            sCreateHsfArgs.mIterations = CeLogin::CeLogin_PBKDF2_Iterations;

            sCreateHsfArgs.mPasswordHashAlgorithm =
                CeLogin::PasswordHash_Production;

            sRc = CeLogin::createCeLoginAcfV1Payload(sCreateHsfArgs, sJson,
                                                     sHash);
        }

        if (CeLogin::CeLoginRc::Success == sRc)
        {
            if (writeBinaryFile(sArgs.mJsonPath, (const uint8_t*)sJson.data(),
                                sJson.length()))
            {
                cout << "Wrote: " << sArgs.mJsonPath << endl;
            }
            else
            {
                cout << "Error writing json file" << endl;
                sRc = CeLogin::CeLoginRc::Failure;
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
                    sRc = CeLogin::CeLoginRc::Failure;
                }
            }

            if (writeBinaryFile(sArgs.mPasswordFile,
                                (const uint8_t*)sCreateHsfArgs.mPasswordPtr,
                                sCreateHsfArgs.mPasswordLength))
            {
                cout << "Wrote: " << sArgs.mPasswordFile << endl;
            }
            else
            {
                cout << "Error writing generated password file" << endl;
                sRc = CeLogin::CeLoginRc::Failure;
            }
        }

        if (sPasswordPtr)
        {
            OPENSSL_secure_clear_free(sPasswordPtr, Prod_PasswordLength);
        }
    }
    else if (sOperation == PackageJsonAndSignature)
    {
        CeLogin::CeLoginCreateHsfArgsV1 sCreateHsfArgs;

        std::vector<uint8_t> sJson;
        std::vector<uint8_t> sSignature;
        std::vector<uint8_t> sAcf;

        sCreateHsfArgs.mSourceFileName =
            sArgs.mComment.empty() ? "" : sArgs.mComment;

        if (!readBinaryFile(sArgs.mJsonPath, sJson))
        {
            cout << "Error reading json file" << endl;
            sRc = CeLogin::CeLoginRc::Failure;
        }
        else if (!readBinaryFile(sArgs.mSignaturePath, sSignature))
        {
            cout << "Error reading signature" << endl;
            sRc = CeLogin::CeLoginRc::Failure;
        }
        else
        {
            // Both Json and Signature files have been read
            string sJsonStr =
                string((char*)sJson.data(), (char*)sJson.data() + sJson.size());
            sRc = CeLogin::createCeLoginAcfV1Asn1(sCreateHsfArgs, sJsonStr,
                                                  sSignature, sAcf);
        }

        if (CeLogin::CeLoginRc::Success == sRc)
        {
            if (writeBinaryFile(sArgs.mOutputFile, (const uint8_t*)sAcf.data(),
                                sAcf.size()))
            {
                cout << "Wrote: " << sArgs.mOutputFile << endl;
            }
            else
            {
                cout << "Error writing final ACF file" << endl;
                sRc = CeLogin::CeLoginRc::Failure;
            }
        }
    }
    else
    {
        cout << "Unknown subcommand option" << endl;
        sRc = CeLogin::CeLoginRc::Failure;
    }

    cout << "RC: " << hex << (int)sRc << endl;

    return sRc;
}
