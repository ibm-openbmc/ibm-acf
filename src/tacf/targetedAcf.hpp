#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
/**
 * TargetedAcf class for targeted access control file (ACF) features.
 */
class TargetedAcf
{
  public:
    enum class TargetedAcfAction
    {
        Invalid,
        Install,
        Authenticate,
        Verify
    };

    /**
     * TargetedAcf object default destructor.
     * @brief destructor
     */
    virtual ~TargetedAcf() = default;

  protected:
    /**
     * Submit an ACF for targeted processing.
     * @brief Process ACF.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param size      The size of the ASN1 encoded binary ACF.
     * @param expires   The ACF expiration date to populate.
     * @param action    The action to perform if the ACF validates.
     * @param password  A pointer to a password for authentication.
     *
     * @return A non-zero error value or zero on success.
     */
    int targetedAuth(const uint8_t* acf, size_t size, std::string& expires,
                     TargetedAcfAction action, const char* password)
    {
        // Get previous anti-replay id.
        uint64_t replay;
        int rc = retrieveReplayId(replay);
        if (!rc)
        {
            // Remember current replay id in case install fails.
            uint64_t originalReplay = replay;

            unsigned int type = acfTypeInvalid;
            std::string auth;
            CeLogin::AcfUserFields acfUserFields;
            // Process the ACF.
            rc = getAuth(acf, size, auth, type, expires, replay, action,
                         password, acfUserFields);

            // If processing successful.
            if (!rc)
            {
                // And action was install.
                if (TargetedAcfAction::Install == action)
                {
                    // Store updated replay Id.
                    if (replay != originalReplay)
                    {
                        rc = storeReplayId(replay);
                    }

                    // If replay id updated.
                    if (!rc)
                    {
                        // And ACF type is admin-reset.
                        switch (type)
                        {
                            case acfTypeAdminReset:
                            {
                                rc = resetAdmin(auth);

                                if (!rc)
                                {
                                    // And remove old ACF.
                                    removeAcf();
                                }
                            }
                            break;
                            case acfTypeService:
                            case acfTypeResourceDump:
                            case acfTypeBmcShell:
                                rc = installAcf(acf, size, type, acfUserFields);
                                break;
                            default:
                                rc = -1;
                                break;
                        }
                        // If install action was not successful.
                        if (rc)
                        {
                            // Restore original replay Id.
                            storeReplayId(originalReplay);
                        }
                    }
                }
            }
            else
            {
                CE_LOG_DEBUG("Targeted getAuth successful failure");
            }
        }
        return rc;
    }

  protected:
    /**
     * @brief Implementation specific value definitions.
     */
    static constexpr unsigned int acfTypeService =
        CeLogin::AcfType::AcfType_Service;

    static constexpr unsigned int acfTypeAdminReset =
        CeLogin::AcfType::AcfType_AdminReset;
    static constexpr unsigned int acfTypeInvalid =
        CeLogin::AcfType::AcfType_Invalid;

    constexpr static unsigned int acfTypeResourceDump =
        CeLogin::AcfType::AcfType_ResourceDump;

    constexpr static unsigned int acfTypeBmcShell =
        CeLogin::AcfType::AcfType_BmcShell;

  private:
    /**
     * Validate ACF and retrieve an associated user auth code, ACF type
     * value and updated ACF replay id.
     * @brief Retrieve user auth, ACF type and replay id.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param size      The size of the ASN1 encoded binary ACF.
     * @param auth      The user auth value to populate.
     * @param type      The ACF type value to populate.
     * @param expires   The ACF expiration date
     * @param replay    The current and updated replay id value.
     * @param action    The type of action to perform with the ACF.
     * @param password  A pointer to a password for authentication.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int getAuth(const uint8_t* acf, size_t size, std::string& auth,
                        unsigned int& type, std::string& expires,
                        uint64_t& replay, TargetedAcfAction action,
                        const char* password,
                        CeLogin::AcfUserFields& acfUserFields) = 0;

    /**
     * Retrieve the current replay id value.
     * @brief Retrieve the replay id.
     *
     * @param replay    The replay id value to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int retrieveReplayId(uint64_t& replay) = 0;

    /**
     * Store the updated replay id value.
     * @brief Store the replay id.
     *
     * @param replay    The replay id value to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int storeReplayId(uint64_t replay) = 0;

    /**
     * Reset the admin account using the associated user auth code.
     * @brief Reset the admin account.
     *
     * @param auth  The associated user auth code.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int resetAdmin(const std::string& auth) = 0;

    /**
     * Remove the previously stored ACF.
     * @brief Remove ACF.
     */
    virtual void removeAcf() = 0;

    /**
     * Install the new ACF.
     * @brief Install ACF.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param size      The size of the ASN1 encoded binary ACF.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int installAcf(const uint8_t* acf, size_t size, unsigned int type,
                           const CeLogin::AcfUserFields& acfUserFields) = 0;
};
