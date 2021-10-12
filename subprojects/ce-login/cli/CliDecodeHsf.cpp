
#include "CeLoginCli.h"
#include "CliCeLoginV1.h"
#include "CliUtils.h"

#include <CeLogin.h>
#include <getopt.h>
#include <inttypes.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace CeLogin;
using namespace std;

struct DecodeArguments
{
    const char* mHsfFileName;
    const char* mPublicKeyFileName;
    bool mVerbose;
    bool mHelp;
    DecodeArguments()
    {
        mHsfFileName = NULL;
        mPublicKeyFileName = NULL;
        mVerbose = false;
        mHelp = false;
    }
};

enum DecodeOptOptions
{
    HsfFileName,
    PublicKeyFileName,
    Help,
    Verbose,
    NOptOptions
};

struct option decode_long_options[NOptOptions + 1] = {
    {"hsfFile", required_argument, NULL, 'i'},
    {"publicKeyFile", required_argument, NULL, 'k'},
    {"help", no_argument, NULL, 'h'},
    {"verbose", no_argument, NULL, 'v'},
    {0, 0, 0, 0}};

string decode_options_description[NOptOptions] = {"HsfFile", "PublicKeyFile",
                                                  "Help", "Verbose"};

void decodeParseArgs(int argc, char** argv, struct DecodeArguments& args)
{
    string short_options = "";

    for (int i = 0; i < NOptOptions; i++)
    {
        short_options += decode_long_options[i].val;
        if (required_argument == decode_long_options[i].has_arg)
        {
            short_options += ":";
        }
    }

    int c;
    int sNumOfRequiredArgumentsFound = 0;
    while (1)
    {
        int option_index = 0;
        c = getopt_long(argc, argv, short_options.c_str(), decode_long_options,
                        &option_index);
        if (c == -1)
            break;
        switch (c)
        {
            case 'i':
            {
                sNumOfRequiredArgumentsFound++;
                args.mHsfFileName = optarg;
                break;
            }
            case 'k':
            {
                sNumOfRequiredArgumentsFound++;
                args.mPublicKeyFileName = optarg;
                break;
            }
            case 'h':
            {
                args.mHelp = true;
                break;
            }
            case 'v':
            {
                args.mVerbose = true;
                break;
            }
            default:
            {
            }
        }
    }
}

void decodePrintHelp(int argc, char** argv)
{
    // Find the longest option
    size_t sLongestOpt = 0;
    for (unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(decode_long_options[i].name);
        sLongestOpt = max<size_t>(sLongestOpt, sLength);
    }

    cout << "Usage: " << argv[0] << " " << argv[1] << endl;
    for (unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(decode_long_options[i].name);
        cout << "\t-" << (char)decode_long_options[i].val << " --"
             << decode_long_options[i].name;
        for (size_t j = 0; j < (sLongestOpt - sLength); j++)
        {
            cout << " ";
        }
        cout << " | " << decode_options_description[i] << endl;
    }
}

bool decodeValidateArgs(const DecodeArguments& args)
{
    bool sIsValidArgs = true;
    if (NULL == args.mHsfFileName)
    {
        sIsValidArgs = false;
        cout << "Error: Missing HsfFileName" << endl;
    }
    return sIsValidArgs;
}

void printDecodedHsf(const CeLogin::CeLoginDecryptedHsfArgsV1& hsfParm,
                     const bool verboseParm)
{
    cout << "ProcessingType:\t" << hsfParm.mProcessingType << endl;
    cout << "SourceFileName:\t" << hsfParm.mSourceFileName << endl;
    cout << "SourceFileData:" << endl;
    cout << "{" << endl;
    cout << "\tmachines: [" << endl;
    for (size_t sIdx = 0; sIdx < hsfParm.mMachines.size(); sIdx++)
    {
        cout << "\t\t{" << endl;
        cout << "\t\t\tserialNumber:\t" << hsfParm.mMachines[sIdx].mSerialNumber
             << endl;
        cout << "\t\t\tframeworkEc:\t" << hsfParm.mMachines[sIdx].mFrameworkEc
             << endl;
        cout << "\t\t}" << endl;
    }
    cout << "\t]" << endl;
    cout << "\thashedAuthCode:\t" << hsfParm.mPasswordHash << endl;
    cout << "\tsalt:\t" << hsfParm.mSalt << endl;
    cout << "\titerations:\t" << hsfParm.mIterations << endl;
    cout << "\texpiration:\t" << hsfParm.mExpirationDate << endl;
    cout << "\trequestId:\t" << hsfParm.mRequestId << endl;
    cout << "}" << endl;
    if (verboseParm)
    {
        cout << endl;
        cout << "Signature:" << endl;
        cout << cli::getHexStringFromBinary(hsfParm.mSignature) << endl;
        cout << endl;
        cout << "Raw Signed Payload:" << endl;
        cout << cli::getHexStringFromBinary(hsfParm.mSignedPayload) << endl;
        cout << endl;
    }
}

CeLogin::CeLoginRc cli::decodeHsf(int argc, char** argv)
{
    DecodeArguments sArgs;
    decodeParseArgs(argc, argv, sArgs);

    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Failure;

    if (sArgs.mHelp)
    {
        decodePrintHelp(argc, argv);
    }
    else if (decodeValidateArgs(sArgs))
    {
        vector<uint8_t> sHsf;
        if (readBinaryFile(sArgs.mHsfFileName, sHsf))
        {
            vector<uint8_t> sPublicKey;
            if (sArgs.mPublicKeyFileName)
            {
                if (!readBinaryFile(sArgs.mPublicKeyFileName, sPublicKey))
                {
                    cout << "ERROR: Unable to read public key file: \""
                         << sArgs.mPublicKeyFileName << "\"" << endl;
                    return sRc;
                }
            }
            else
            {
                sPublicKey.clear();
            }

            CeLogin::CeLoginDecryptedHsfArgsV1 sDecodedHsf;
            sRc = CeLogin::decodeAndVerifyCeLoginHsfV1(sHsf, sPublicKey,
                                                       sDecodedHsf);
            if (CeLoginRc::Success == sRc)
            {
                printDecodedHsf(sDecodedHsf, sArgs.mVerbose);
                if (!sPublicKey.empty())
                    cout << "Signature verified" << endl;
                else
                    cout << "Signature validation skipped" << endl;
            }
            else if (CeLoginRc::SignatureNotValid == sRc)
            {
                cout << "Signature is not valid" << endl;
            }
            else
            {
                cout << "Error: 0x" << hex << (int)sRc << endl;
            }
        }
        else
        {
            cout << "ERROR: Unable to read hsf file: \"" << sArgs.mHsfFileName
                 << "\"" << endl;
        }
    }
    else
    {
        cout << "Args failed to validate" << endl;
    }

    return sRc;
}
