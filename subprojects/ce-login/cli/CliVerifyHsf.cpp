
#include "CeLoginCli.h"
#include "CliUtils.h"

#include <CeLogin.h>
#include <getopt.h>
#include <inttypes.h>
#include <string.h>

#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace CeLogin;

// clang-format off
struct VerifyArguments
{
    std::string mHsfFileName;
    std::string mPublicKeyFileName;
    std::string mPassword;
    std::string mSerialNumber;
    bool mVerbose;
    bool mHelp;
    VerifyArguments()
    {
        mVerbose = false;
        mHelp = false;
    }
};

enum VerifyOptOptions
{
    HsfFileName,
    PublicKeyFileName,
    Password,
    SerialNumber,
    Help,
    Verbose,
    NOptOptions
};

struct option verify_long_options[NOptOptions + 1] = {
    {"hsfFile", required_argument, NULL, 'i'},
    {"publicKeyFile", required_argument, NULL, 'k'},
    {"password", required_argument, NULL, 'p'},
    {"serialNumber", required_argument, NULL, 's'},
    {"help", no_argument, NULL, 'h'},
    {"verbose", no_argument, NULL, 'v'},
    {0, 0, 0, 0}};

std::string verify_options_description[NOptOptions] = {
    "HsfFile",
    "PublicKeyFile",
    "Password",
    "<7-char serial number|UNSET>",
    "Help",
    "Verbose"};
// clang-format on

void verifyParseArgs(int argc, char** argv, struct VerifyArguments& args)
{
    std::string short_options = "";

    for (int i = 0; i < NOptOptions; i++)
    {
        short_options += verify_long_options[i].val;
        if (required_argument == verify_long_options[i].has_arg)
        {
            short_options += ":";
        }
    }

    int c;
    int sNumOfRequiredArgumentsFound = 0;
    while (1)
    {
        int option_index = 0;
        c = getopt_long(argc, argv, short_options.c_str(), verify_long_options,
                        &option_index);
        if (c == -1)
            break;
        switch (c)
        {
            case 'i':
            {
                sNumOfRequiredArgumentsFound++;
                args.mHsfFileName = std::string(optarg);
                break;
            }
            case 'k':
            {
                sNumOfRequiredArgumentsFound++;
                args.mPublicKeyFileName = std::string(optarg);
                break;
            }
            case 'p':
            {
                sNumOfRequiredArgumentsFound++;
                args.mPassword = std::string(optarg);
                break;
            }
            case 's':
            {
                sNumOfRequiredArgumentsFound++;
                args.mSerialNumber = std::string(optarg);
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

void verifyPrintHelp(int argc, char** argv)
{
    // Find the longest option
    size_t sLongestOpt = 0;
    for (unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(verify_long_options[i].name);
        sLongestOpt = std::max<size_t>(sLongestOpt, sLength);
    }

    std::cout << "Usage: " << argv[0] << " " << argv[1] << std::endl;
    for (unsigned int i = 0; i < NOptOptions; i++)
    {
        size_t sLength = strlen(verify_long_options[i].name);
        std::cout << "\t-" << (char)verify_long_options[i].val << " --"
                  << verify_long_options[i].name;
        for (size_t j = 0; j < (sLongestOpt - sLength); j++)
        {
            std::cout << " ";
        }
        std::cout << " | " << verify_options_description[i] << std::endl;
    }
}

bool verifyValidateArgs(const VerifyArguments& args)
{
    bool sIsValidArgs = true;
    if (args.mHsfFileName.empty())
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing HsfFileName" << std::endl;
    }
    if (args.mPublicKeyFileName.empty())
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing Public Key File Path" << std::endl;
    }
    if (args.mPassword.empty())
    {
        std::cout
            << "Warning: Missing Password. Performing integrity/upload check only"
            << std::endl;
    }
    if (args.mSerialNumber.empty())
    {
        sIsValidArgs = false;
        std::cout << "Error: Missing Serial Number" << std::endl;
    }
    return sIsValidArgs;
}

CeLogin::CeLoginRc cli::verifyHsf(int argc, char** argv)
{
    VerifyArguments sArgs;
    verifyParseArgs(argc, argv, sArgs);

    CeLogin::CeLoginRc sRc = CeLogin::CeLoginRc::Failure;

    if (sArgs.mHelp)
    {
        verifyPrintHelp(argc, argv);
    }
    else if (verifyValidateArgs(sArgs))
    {
        std::vector<uint8_t> sHsf;
        if (readBinaryFile(sArgs.mHsfFileName, sHsf))
        {
            std::vector<uint8_t> sPublicKey;
            if (readBinaryFile(sArgs.mPublicKeyFileName, sPublicKey))
            {
                std::time_t sTime = std::time(NULL);
                CeLogin::ServiceAuthority sAuth = CeLogin::ServiceAuth_None;
                uint64_t sExpiration = 0;

                if (!sArgs.mPassword.empty())
                {
                    // Perform full authorization validation
                    sRc = CeLogin::getServiceAuthorityV1(
                        sHsf.data(), sHsf.size(), sArgs.mPassword.data(),
                        sArgs.mPassword.size(), sTime, sPublicKey.data(),
                        sPublicKey.size(), sArgs.mSerialNumber.data(),
                        sArgs.mSerialNumber.size(), sAuth, sExpiration);
                }
                else
                {
                    // Verify ACF integrity, skip password validation
                    sRc = CeLogin::checkServiceAuthorityAcfIntegrityV1(
                        sHsf.data(), sHsf.size(), sTime, sPublicKey.data(),
                        sPublicKey.size(), sArgs.mSerialNumber.data(),
                        sArgs.mSerialNumber.size(), sAuth, sExpiration);
                }

                if (CeLoginRc::Success == sRc)
                {
                    if (sArgs.mPassword.empty())
                    {
                        std::cout << "ACF is valid, skipped password check"
                                  << std::endl;
                    }
                    else
                    {
                        std::cout << "ACF/password is valid" << std::endl;
                    }
                }
                else if (CeLoginRc::SignatureNotValid == sRc)
                {
                    std::cout << "Signature is not valid" << std::endl;
                }
                else
                {
                    std::cout << "Error: Component \"" << (int)sRc.mComponent
                              << "\" Reason: 0x" << std::hex << (int)sRc.mReason
                              << std::endl;
                    std::cout << "Error: " << sRc << std::endl;
                }
                switch (sAuth)
                {
                    case CeLogin::ServiceAuth_None:
                    {
                        std::cout << "Authorization: None" << std::endl;
                        break;
                    }
                    case CeLogin::ServiceAuth_User:
                    {
                        std::cout << "Authorization: User" << std::endl;
                        break;
                    }
                    case CeLogin::ServiceAuth_CE:
                    {
                        std::cout << "Authorization: CE" << std::endl;
                        break;
                    }
                    case CeLogin::ServiceAuth_Dev:
                    {
                        std::cout << "Authorization: Dev" << std::endl;
                        break;
                    }
                    default:
                    {
                        std::cout << "Authorization: Unknown" << std::endl;
                        break;
                    }
                }
                printf("Expiration (UNIX): %llu\n", sExpiration);
            }
            else
            {
                std::cout << "ERROR: Unable to read public key file: \""
                          << sArgs.mPublicKeyFileName << "\"" << std::endl;
            }
        }
        else
        {
            std::cout << "ERROR: Unable to read hsf file: \""
                      << sArgs.mHsfFileName << "\"" << std::endl;
        }
    }
    else
    {
        std::cout << "Args failed to validate" << std::endl;
    }

    return sRc;
}
