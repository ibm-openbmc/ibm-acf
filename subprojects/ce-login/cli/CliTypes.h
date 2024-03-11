#include <array>
#include <string>
#include <sys/types.h>
#include <vector>

#include <CeLogin.h>

#ifndef _CLITYPES_H
#define _CLITYPES_H

namespace cli
{
    enum ProcessorGeneration
    {
        Invalid = 0,
        P10     = 10,
        P11     = 11,
    };

    struct Machine
    {
        Machine() : mSerialNumber(), mAuth(CeLogin::ServiceAuth_None), mProc(Invalid)
        {}

        Machine(const std::string& serialNumberParm,
                const CeLogin::ServiceAuthority authParm,
                const ProcessorGeneration procGenParm) :
            mSerialNumber(serialNumberParm),
            mAuth(authParm), mProc(procGenParm)
        {}

        std::string               mSerialNumber;
        CeLogin::ServiceAuthority mAuth;
        ProcessorGeneration       mProc;
    };

}; // namespace cli

#endif
