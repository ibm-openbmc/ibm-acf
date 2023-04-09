#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>

#include <tacf.hpp>

#include <filesystem>

// RUN_UNIT_TESTS should only be enabled when running
// meson unit tests, otherwise this shoudn't be enabled
#ifdef RUN_UNIT_TESTS
#include "testconf.h"
// print logs to stdout under test
#define pam_syslog(X, Y, ...) printf(__VA_ARGS__)
#endif

const char* default_user = "service";

// Determine the user name of the auth attempt.
// Returns:
//    PAM_SUCCESS for the special service user.
//    {any retcode} if pam_get_user failed.
//    PAM_IGNORE otherwise.
int ignore_other_accounts(pam_handle_t* pamh, const char* user_parm)
{
    const char* login_user = nullptr;
    int retval             = pam_get_user(pamh, &login_user, nullptr);
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_NOTICE, "Unable to get user name: %s\n",
                   pam_strerror(pamh, retval));
        return retval;
    }
    if (0 != strcmp(user_parm, login_user))
    {
        return PAM_IGNORE;
    }
    return PAM_SUCCESS;
}

bool readBinaryFile(const std::string fileNameParm,
                    std::vector<uint8_t>& bufferParm)
{
    std::ifstream sInputFile;
    if (fileNameParm.empty())
    {
        return false;
    }

    // Open the file.
    sInputFile.open(fileNameParm.c_str(), std::ios::binary);
    sInputFile.unsetf(std::ios::skipws);
    if (!sInputFile)
    {
        return false;
    }

    // Get the size of the file.
    std::error_code ec;
    std::filesystem::path path = fileNameParm;
    std::uintmax_t size        = std::filesystem::file_size(path, ec);
    if (ec)
    {
        return false;
    }

    // Read the file.
    bufferParm.reserve(size);
    bufferParm.assign(size, 0);
    sInputFile.read((char*)bufferParm.data(), size);
    sInputFile.close();

    return true;
}

#ifdef RUN_UNIT_TESTS
int fieldModeEnabled = 1;
string mSerialNumber = "UNSET";
// manually set variables (fieldModeEnabled and mSerialNumber)
// for googletest for as dbus objects
// aren't available on non OpenBMC targets
void setFieldModeProperty(int fieldModeEnabledParam)
{
    fieldModeEnabled = fieldModeEnabledParam;
}

void setSerialNumberProperty(const string& obj)
{
    mSerialNumber = obj;
}
#else
int readFieldMode(pam_handle_t* pamh)
{
    FILE* pipe = popen("fw_printenv -n fieldmode 2>&1", "r");
    if (!pipe)
    {
        pam_syslog(pamh, LOG_ERR, "popen failed\n");
        return PAM_SYSTEM_ERR;
    }
    std::array<char, 512> buffer;
    std::stringstream result;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
    {
        result << buffer.data();
    }
    int stat = pclose(pipe);
    if (WIFEXITED(stat))
    {
        // Handle expected results
        int rc = WEXITSTATUS(stat);
        if (rc == 0)
        {
            // fw_printenv exited normally with rc=0
            if (0 == strcmp(result.str().c_str(), "true\n"))
            {
                return 1; // fieldmode=true
            }
            return 0; // any other value means fieldmode=false
        }
        // fw_printenv exited normally with nonzero rc
        if (0 == strcmp(result.str().c_str(),
                        "## Error: \"fieldmode\" not defined\n"))
        {
            return 0; // fieldmode not set means fieldmode=false
        }
    }
    // Something unexpected happened.  Either fw_printenv exited abnormally,
    // or gave unexpected results, or something else unexpected happened.
    pam_syslog(pamh, LOG_ERR, "pclose failed stat=0x%X, message=%s\n", stat,
               result.str().c_str());
    return -1; // This should never happen
}
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
#ifdef HAVE_PAM_FAIL_DELAY
    pam_fail_delay(pamh, 2'000'000);
#endif // HAVE_PAM_FAIL_DELAY

    const char* username = nullptr;

    // Only handle the service user.
    int retval = -1;
    retval     = pam_get_user(pamh, &username, nullptr);

    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    else if (strcmp(default_user, username))
    {
        return PAM_IGNORE;
    }

    // Get the user's password
    const char* password;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, nullptr);

    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_WARNING, "Unable to get password\n");
        return PAM_AUTH_ERR;
    }

    // Specify logging and get field mode overrides.
    Tacf tacf{
        [](void* pamh, std::string msg) {
            pam_syslog((pam_handle_t*)pamh, LOG_WARNING, "%s", msg.c_str());
        },
        [](void* pamh) -> int { return readFieldMode((pam_handle_t*)pamh); },
        pamh};

    // And authenticate user with password.
    int rc = tacf.authenticate(password);
    if (Tacf::tacfSuccess == rc)
    {
        return PAM_SUCCESS;
    }
    else
    {
        // Log the error
        std::string errMsg = "Auth Error";
        if (Tacf::tacfSystemError == rc)
        {
            errMsg = "System Error";
        }

        pam_syslog(pamh, LOG_WARNING, "ACF service auth failed 0x%X: %s", rc,
                   errMsg.c_str());
    }
    return Tacf::tacfAuthError == rc ? PAM_AUTH_ERR : PAM_SYSTEM_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc,
                              const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
    // Only handle the service user.
    const char* user_parm = default_user;
    int retval            = ignore_other_accounts(pamh, user_parm);
    if (retval == PAM_IGNORE)
    {
        retval = PAM_PERM_DENIED;
    }
    return retval;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc,
                                    const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
    // Only handle the service user.  Reject all password changes.
    const char* user_parm = default_user;
    int retval            = ignore_other_accounts(pamh, user_parm);
    switch (retval)
    {
        case PAM_SUCCESS:
            retval = PAM_AUTHTOK_ERR;
            break;

        case PAM_IGNORE:
            retval = PAM_SUCCESS;
            break;
    }

    return retval;
}
