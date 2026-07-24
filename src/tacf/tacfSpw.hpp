#pragma once

#include <errno.h>
#include <grp.h>
#include <pwd.h>
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
    static constexpr auto spwFilePath     = "/etc/shadow";
    static constexpr auto pwFilePath      = "/etc/passwd";
    static constexpr auto noPassword      = "x";
    static constexpr auto invalidPassword = "*";
    static constexpr auto noUserHome      = "/nonexistent";
    static constexpr auto noUserShell     = "/sbin/nologin";

  public:
    /**
     * Reset the user password if the user exists.
     * @brief Reset the user password.
     *
     * @param userName  Name of the user to reset.
     * @param userSpw   The value to use for user shadow password.
     *
     * @return A non-zero error value or zero on success.
     */
    int resetUserPassword(const std::string& userName,
                          const std::string& userSpw)
    {
        // If user does not exist we can not reset.
        if (nullptr == getspnam(userName.c_str()))
        {
            // Signal ok to cleanup and return.
            endspent();
            return 1;
        }

        // Set the user shadow password.
        return spwSetSpw(userName, userSpw);
    }

    /**
     * Create the user passwd file entry if user does not exist.
     * @brief Create the user the user.
     *
     * @param userName  Name of the user to reset.
     *
     * @return A non-zero error value or zero on success.
     */
    int createUser(const std::string& userName)
    {
        // If user exists in shadow and passwd we are done.
        if (nullptr != getpwnam(userName.c_str()) &&
            nullptr != getspnam(userName.c_str()))
        {
            // Signal ok to cleanup and return.
            endpwent();
            return 0;
        }

        return spwCreateUser(userName, spwGetUid(userName),
                             spwGetGid(userName));
    }

  private:
    FILE* spwFile = nullptr;
    FILE* pwFile  = nullptr;

    /**
     * Update the user shadow password and expire the password.
     * @brief Update the shadow password.
     *
     * @param spw  The value to set as the shadow password.
     * @param name The name of the user.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwSetSpw(const std::string& name, const std::string& spw)
    {
        int rc = 1;

        // Need name, password and access to shadow password file.
        if (name.empty() || spw.empty() || spwBegin())
        {
            return rc;
        }

        // Read shadow entries from file instead of database.
        FILE* spwFileRead = fopen(spwFilePath, "r");
        if (nullptr == spwFileRead)
        {
            spwEnd();
            return rc;
        }

        spwd* spwDbEntry;
        spwd spwEntry = {};
        bool found = false;

        // Read each shadow password entry.
        while ((spwDbEntry = fgetspent(spwFileRead)))
        {
            // If user entry found save for later and skip.
            if (name == spwDbEntry->sp_namp)
            {
                spwEntry           = *spwDbEntry;
                spwEntry.sp_namp   = (char*)name.c_str();
                spwEntry.sp_pwdp   = (char*)spw.c_str();
                spwEntry.sp_lstchg = 0;
                found = true;
                continue;
            }
            // Write shadow password entry to shadow password file.
            putspent(spwDbEntry, spwFile);
        }

        // Write updated user entry only if found in the flat shadow file.
        if (found)
        {
            rc = putspent(&spwEntry, spwFile);
        }

        // Close the read file handle.
        fclose(spwFileRead);

        spwEnd();
        return rc;
    }

    /**
     * Create an entry in the passwd file.
     * @brief Add to passwd file.
     *
     * @param entryName Name of the entry to create.
     * @param userId    Uid for the entry.
     * @param groupId   Gid for the entry.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwCreatePasswdEntry(const std::string& entryName, uid_t userId,
                             uid_t groupId)
    {
        // Rquires valid name, uid and gid.
        if (entryName.empty() || !userId || !groupId)
        {
            return 1;
        }
        // Create user passwd file entry
        passwd pwEntry = {(char*)entryName.c_str(),
                          (char*)noPassword,
                          userId,
                          groupId,
                          nullptr,
                          (char*)noUserHome,
                          (char*)noUserShell};
        // Write user record to passwd file
        fseek(pwFile, 0, SEEK_END);
        return putpwent(&pwEntry, pwFile);
    }

    /**
     * Create an entry in the shadow file.
     * @brief Add to shadow file.
     *
     * @param entryName  Name of the entry to add.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwCreateShadowEntry(const std::string& entryName)
    {
        // Requires valid name.
        if (entryName.empty())
        {
            return 1;
        }
        // Create user shadow file entry.
        spwd spwEntry = {(char*)entryName.c_str(),
                         (char*)invalidPassword,
                         0,
                         0,
                         99999,
                         7,
                         -1,
                         -1,
                         0};
        // Write user record to shadow file
        fseek(spwFile, 0, SEEK_END);
        return putspent(&spwEntry, spwFile);
    }

    /**
     * Create the user passwd file entry.
     * @brief Create the user passwd entry.
     *
     * @param user      Name of the user to create.
     * @param userId    Uid of the user.
     * @param groupId   Gid of the user.
     *
     * @return A non-zero error value or zero on success.
     */
    int spwCreateUser(const std::string& userName, uid_t userId, uid_t groupId)
    {
        int rc = spwBegin();

        // Create passwd entry if it does not exist.
        if (!rc && nullptr == getpwnam(userName.c_str()))
        {
            rc = spwCreatePasswdEntry(userName, userId, groupId);
        }
        // Create shadow entry if it does not exist.
        if (!rc && nullptr == getspnam(userName.c_str()))
        {
            rc = spwCreateShadowEntry(userName);
        }

        spwEnd();
        return rc;
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
            off_t fpos = ftello(spwFile);

            // If file was changed then size may have changed.
            if (0 != fpos)
            {
                if (ftruncate(fileno(spwFile), fpos) < 0)
                {
                    rc = 1;
                }
            }

            // Close the shadow password file.
            fclose(spwFile);

            spwFile = nullptr;
        }
        return rc;
    }

    /**
     * Update passwd file size and close file.
     * @brief Close passwd file.
     *
     * @return A non-zero error value or zero on success.
     */
    int pwClose()
    {
        int rc = 0;

        // Verify we have passwd file opened.
        if (nullptr != pwFile)
        {
            // Close the shadow password file.
            fclose(pwFile);
        }

        pwFile = nullptr;

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
     * Open the passwd file for reading and writing.
     * @brief Open passwd file.
     *
     * @return A non-zero error value or zero on success.
     */
    int pwOpen()
    {
        // Verify passwd file not opened.
        if (nullptr != pwFile)
        {
            return 1;
        }

        // Open the passwd file.
        pwFile = fopen(pwFilePath, "a+");

        return nullptr == pwFile ? 1 : 0;
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

        // If can not open password files.
        if (spwOpen() || pwOpen())
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
        // Close password files.
        spwClose();
        pwClose();

        // Release password database resources.
        endspent();
        endpwent();

        // Release shadow password file.
        ulckpwdf();
    }

    /**
     * Get exisiting gid or find an available gid.
     * @brief Get gid.
     *
     * @param groupName Group to get gid for.
     *
     * @return A non-zero error value or zero on success.
     */
    uid_t spwGetGid(const std::string& groupName)
    {
        uid_t gid = 0;

        // Get group info from group database.
        group* groupEntry = getgrnam(groupName.c_str());

        // If user group exists get gid.
        if (nullptr != groupEntry)
        {
            gid = groupEntry->gr_gid;
        }
        else
        {
            // Try to find an available gid.
            uid_t groupId = 1000;
            errno         = 0;

            while (groupId <= 9999 &&
                   (!(nullptr == getgrgid(groupId) && 0 == errno)))
            {
                groupId++;
                errno = 0;
            }

            // Found an available gid.
            if (groupId <= 9999)
            {
                gid = groupId;
            }
        }

        return gid;
    }

    /**
     * Get exisiting uid or find an available uid.
     * @brief Get uid.
     *
     * @param userName  User to get uid for.
     *
     * @return A non-zero error value or zero on success.
     */
    uid_t spwGetUid(const std::string& userName)
    {
        uid_t uid = 0;

        // Get user info from passwd database.
        passwd* passwdEntry = getpwnam(userName.c_str());

        // If user exists get uid.
        if (nullptr != passwdEntry)
        {
            uid = passwdEntry->pw_uid;
        }
        else
        {
            // Try to find an available uid.
            uid_t userId = 1000;
            errno        = 0;

            while (userId <= 9999 &&
                   (!(nullptr == getpwuid(userId) && 0 == errno)))
            {
                userId++;
                errno = 0;
            }

            // Found an available uid.
            if (userId <= 9999)
            {
                uid = userId;
            }
        }

        return uid;
    }
};
