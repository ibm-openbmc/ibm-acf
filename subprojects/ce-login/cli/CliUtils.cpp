#include "CliUtils.h"

#include "CliCeLoginV1.h"

#include <CeLogin.h>
#include <getopt.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <string.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

bool cli::readBinaryFile(const std::string fileNameParm,
                         std::vector<uint8_t>& bufferParm)
{
    std::ifstream sInputFile;
    if (!fileNameParm.empty())
    {
        sInputFile.open(fileNameParm.c_str(), std::ios::in | std::ios::binary);
        if (sInputFile.is_open())
        {
            // Get the size of the file
            sInputFile.seekg(0, std::ios::end);
            std::streampos size = sInputFile.tellg();
            sInputFile.seekg(0, std::ios::beg);

            bufferParm.reserve(size);
            bufferParm.assign(size, 0);

            sInputFile.read((char*)bufferParm.data(), size);
            sInputFile.close();

            return true;
        }
        else
        {
            std::cout << "Failed to open file for reading : " << fileNameParm
                      << std::endl;
        }
    }
    else
    {
        std::cout << "filename empty" << std::endl;
    }

    return false;
}

bool cli::writeBinaryFile(const std::string fileNameParm,
                          const uint8_t* bufferParm,
                          const uint64_t bufferLengthParm)
{
    std::ofstream sOutputFile;
    if (!fileNameParm.empty() && bufferParm)
    {
        sOutputFile.open(fileNameParm.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
        if (sOutputFile.is_open())
        {
            sOutputFile.write((const char*)bufferParm, bufferLengthParm);
            sOutputFile.close();
            return true;
        }
        else
        {
            std::cout << "Failed to open file for writing : " << fileNameParm
                      << std::endl;
        }
    }
    else
    {
        std::cout << "write-error: filename empty" << std::endl;
    }
    return false;
}

std::string cli::getHexStringFromBinary(const std::vector<uint8_t>& binaryParm)
{
    std::stringstream ss;

    for (uint64_t sIdx = 0; sIdx < binaryParm.size(); sIdx++)
    {
        ss.fill('0');
        ss.width(2);
        ss << std::hex << (int)binaryParm[sIdx];
    }
    return ss.str();
}

std::string cli::generateReplayId()
{
    const std::time_t sUnixTime = std::time(nullptr);
    const uint64_t sReplayId = static_cast<uint64_t>(sUnixTime);

    return std::to_string(sReplayId);
}

bool cli::generateEtcPasswdHash(const char* pwParm, const std::size_t pwLenParm,
                                std::string& saltParm, std::string& hashParm)
{
    bool sSuccess = false;
    std::string sStdOut;
    std::stringstream sCmd;

    // -6 corresponds to SHA512
    sCmd << "openssl passwd -6"
         << " -salt " << saltParm
         << " " << pwParm;

    FILE* sPipe = popen(sCmd.str().c_str(), "r");
    if(nullptr != sPipe)
    {
        const std::size_t sReadBufferSize = 1024;
        char sReadBuffer[sReadBufferSize];

        while(!feof(sPipe))
        {
            if(nullptr != fgets(sReadBuffer, sReadBufferSize, sPipe))
            {
                sStdOut += sReadBuffer;
            }
        }

        int sRc = pclose(sPipe);
        sSuccess = (EXIT_SUCCESS == sRc);
    }

    if(sSuccess)
    {
        sStdOut.erase(std::remove(sStdOut.begin(), sStdOut.end(), '\n'),
                      sStdOut.end());
        hashParm = sStdOut;
    }

    return sSuccess;
}

bool cli::getIntFromJson(json_object* jsonObjectParm, const std::string keyParm,
                         int32_t& resultIntParm)
{
    bool sSuccess = false;
    if (jsonObjectParm)
    {
        json_object* sSubObject = NULL;
        bool sResult = json_object_object_get_ex(jsonObjectParm, keyParm.data(),
                                                 &sSubObject);
        if (sResult && sSubObject)
        {
            resultIntParm = json_object_get_int(sSubObject);
            sSuccess = true;
        }
    }
    return sSuccess;
}

bool cli::getStringFromJson(json_object* jsonObjectParm,
                            const std::string keyParm,
                            std::string& resultStringParm)
{
    bool sSuccess = false;
    if (jsonObjectParm)
    {
        json_object* sSubObject = NULL;
        bool sResult = json_object_object_get_ex(jsonObjectParm, keyParm.data(),
                                                 &sSubObject);
        if (sResult && sSubObject)
        {
            const int sStringLength = json_object_get_string_len(sSubObject);
            if (sStringLength > 0)
            {
                const char* sString = json_object_get_string(sSubObject);
                resultStringParm = std::string(sString, sStringLength);
                sSuccess = true;
            }
        }
    }
    return sSuccess;
}

bool cli::createSha512PasswordHash(const uint8_t* passwordParm,
                                   const uint64_t lengthParm,
                                   std::vector<uint8_t>& outputHashParm)
{
    if (!passwordParm || 0 == lengthParm)
    {
        return false;
    }

    std::vector<uint8_t> sSha512Digest(SHA512_DIGEST_LENGTH);
    uint8_t* sHashResult =
        SHA512(passwordParm, lengthParm, sSha512Digest.data());

    if (sSha512Digest.data() == sHashResult)
    {
        outputHashParm = sSha512Digest;
    }
    else
    {
        return false;
    }

    return true;
}

bool cli::parseMachineFromString(const std::string& stringParm,
                                 cli::Machine& machineParm)
{
    using namespace std;
    bool sIsSuccess = false;

    size_t sCount = count(stringParm.begin(), stringParm.end(), ',');
    if (2 == sCount)
    {
        size_t sFirstDelimiter = stringParm.find(',');
        size_t sSecondDelimiter = stringParm.find(',', sFirstDelimiter + 1);

        string sProcStr = stringParm.substr(0, sFirstDelimiter);
        string sAuthStr = stringParm.substr(
            sFirstDelimiter + 1, sSecondDelimiter - sFirstDelimiter - 1);
        string sSerialStr = stringParm.substr(
            sSecondDelimiter + 1, stringParm.length() - sSecondDelimiter - 1);

        // TODO: force sProcStr and sAuthStr to a consistant case for better
        // parsing

        if (0 == sProcStr.compare("P10"))
        {
            CeLogin::ServiceAuthority sAuth = CeLogin::ServiceAuth_None;
            if (0 == sAuthStr.compare("dev"))
            {
                sAuth = CeLogin::ServiceAuth_Dev;
            }
            else if (0 == sAuthStr.compare("ce"))
            {
                sAuth = CeLogin::ServiceAuth_CE;
            }

            if (CeLogin::ServiceAuth_None != sAuth)
            {
                if (!sSerialStr.empty())
                {
                    machineParm.mAuth = sAuth;
                    machineParm.mProc = cli::P10;
                    machineParm.mSerialNumber = sSerialStr;
                    sIsSuccess = true;
                }
            }
        }
        else if (0 == sProcStr.compare("P11"))
        {
            CeLogin::ServiceAuthority sAuth = CeLogin::ServiceAuth_None;
            if (0 == sAuthStr.compare("dev"))
            {
                sAuth = CeLogin::ServiceAuth_Dev;
            }
            else if (0 == sAuthStr.compare("ce"))
            {
                sAuth = CeLogin::ServiceAuth_CE;
            }

            if (CeLogin::ServiceAuth_None != sAuth)
            {
                if (!sSerialStr.empty())
                {
                    machineParm.mAuth = sAuth;
                    machineParm.mProc = cli::P11;
                    machineParm.mSerialNumber = sSerialStr;
                    sIsSuccess = true;
                }
            }
        }
    }
    return sIsSuccess;
}

void cli::printHelp(const char* cmdParm, const char* subCmdParm,
                    const std::string& introParagraphParm,
                    const option optionsParm[], std::string descriptionParm[],
                    const uint64_t numOptionsParm)
{
    // Find the longest option
    size_t sLongestOpt = 0;
    for (size_t i = 0; i < numOptionsParm; i++)
    {
        size_t sLength = strlen(optionsParm[i].name);
        sLongestOpt = std::max<size_t>(sLongestOpt, sLength);
    }

    std::cout << "Usage: " << cmdParm << " " << subCmdParm << std::endl;

    if (!introParagraphParm.empty())
    {
        std::cout << std::endl << introParagraphParm << std::endl << std::endl;
    }

    for (unsigned int i = 0; i < numOptionsParm; i++)
    {
        size_t sLength = strlen(optionsParm[i].name);
        std::cout << "\t-" << (char)(optionsParm[i].val) << " --"
                  << optionsParm[i].name;
        for (size_t j = 0; j < (sLongestOpt - sLength); j++)
        {
            std::cout << " ";
        }
        std::cout << " | " << descriptionParm[i] << std::endl;
    }
}
