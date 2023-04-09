#pragma once

#include <shadow.h>
#include <unistd.h>

#include <iostream>

/**
 * TacfSpw class for manipulating the linux shadow file
 */
class TacfSpw
{
    /*
     * @brief Implementation specific value definitions.
     */
    static constexpr auto spwFilePath = "/etc/shadow";
    static constexpr auto adminName   = "admin";

  public:
    /**
     * Reset the admin user account.
     * @brief Reset the admin.
     *
     * @param adminSpw  The value to use for admin user shadow password.
     *
     * @return A non-zero error value or zero on success.
     */
    int resetAdmin(const std::string& adminSpw)
    {
        // Prepare for shadow password database access.
        setspent();

        // If admin user does not exist we can not reset.
        if (nullptr == getspnam(adminName))
        {
            endspent();
            return 1;
        }

        // Reset the admin user shadow password.
        return spwSetSpw(adminName, adminSpw);
    }

  private:
    FILE* spwFile = nullptr;

    /**
     * Update the admin user shadow password and expire the password.
     * @brief Reset the admin user account password.
     *
     * @param adminSpw  The value to set as the admin user shadow password.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwSetSpw(const std::string& name, const std::string& spw)
    {
        // Need name, password and access to shadow password file.
        if (name.empty() || spw.empty() || spwBegin())
        {
            return 1;
        }

        spwd* spwDbEntry;
        spwd spwEntry;

        // Read each shadow password entry.
        while ((spwDbEntry = getspent()))
        {
            // If the admin user name is found, save the details and skip.
            if (name == spwDbEntry->sp_namp)
            {
                spwEntry           = *spwDbEntry;
                spwEntry.sp_namp   = (char*)name.c_str(); // not needed
                spwEntry.sp_pwdp   = (char*)spw.c_str();
                spwEntry.sp_lstchg = 0;
                continue;
            }
            // Write shadow password entry to shadow password file.
            putspent(spwDbEntry, spwFile);
        }
        // Write admin user entry, will discard if empty.
        putspent(&spwEntry, spwFile);

        // Finished with password database and file.
        spwEnd();

        return 0;
    }

    /**
     * Update shadow password file size and close file.
     * @brief Close shadow password file.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwClose()
    {
        int rc = 0;

        // Verify we have shadow password file opened.
        if (nullptr != spwFile)
        {
            // Files size may have changed so truncate.
            long int fsize = ftell(spwFile);
            if (ftruncate(fileno(spwFile), fsize) < 0)
            {
                rc = 1;
            }

            // Close the shadow password file.
            fclose(spwFile);
        }

        spwFile = nullptr;

        return rc;
    }

    /**
     * Open the shadow password file for reading and writing.
     * @brief Open shadow password file.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwOpen()
    {
        // Verify shadow password file not opened.
        if (nullptr != spwFile)
        {
            return 1;
        }

        // Open the shadow password file.
        spwFile = fopen(spwFilePath, "r+");

        return nullptr == spwFile ? 1 : 0;
    }

    /**
     * Initialize shadow password database and open shadow password file.
     * @brief Begin shadow password file changes.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwBegin()
    {
        int unlocked, lcount = 4;

        // Try to reserve access to shadow password file
        do
        {
            unlocked = lckpwdf();
            lcount--;
        } while (unlocked && lcount);

        // Not able to reserve.
        if (unlocked)
        {
            return 1;
        }

        // Initialize shadow password database.
        setspent();

        // If can not open shadow password file.
        if (spwOpen())
        {
            // Relese shadow password resources.
            spwEnd();

            return 1;
        }

        return 0;
    }

    /**
     * Release shadow password database and shadow password file.
     * @brief End shadow password file changes.
     *
     * @return A non-zero error value or zero on success.
     */
    void spwEnd()
    {
        // Close shadow password file.
        spwClose();

        // Release shadow password database resources.
        endspent();

        // Release shadow password file.
        ulckpwdf();
    }
};
