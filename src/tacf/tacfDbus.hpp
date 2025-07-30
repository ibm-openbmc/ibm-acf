#pragma once

#include <ce_logger.hpp>
#include <sdbusplus/bus.hpp>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>
/**
 * TacfBus class for interacting with dbus objects.
 */
class TacfDbus
{
  public:
    /**
     * @brief Types of properties expected to be read.
     */
    using PropertyVariant =
        std::variant<std::vector<uint8_t>, std::string, bool>;

    /**
     * Retrieve the serial number using dbus get properties interface.
     * @brief retrieve the serial number.
     *
     * @param serial    serial number value to populate.
     *
     * @return a non-zero error value or zero on success.
     */
    int retrieveSerialNumber(std::string& serial) const
    {
        PropertyVariant message;

        if (dbusGetProperty("xyz.openbmc_project.Inventory.Manager",
                            "/xyz/openbmc_project/inventory/system",
                            "xyz.openbmc_project.Inventory.Decorator.Asset",
                            "SerialNumber", message))
        {
            return 1;
        }

        // Serial number is a string type.
        if (auto value = std::get_if<std::string>(&message))
        {
            serial = *value;
        }
        else
        {
            return 1;
        }

        return 0;
    }

    /**
     * Retrieve the field mode state using dbus get properties interface.
     * @brief Retrieve field mode state.
     *
     * @param enabled    Field mode enabled state to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    int retrieveFieldMode(bool& enabled) const
    {
        enabled = false;

        PropertyVariant message;

        if (dbusGetProperty("xyz.openbmc_project.Software.BMC.Updater",
                            "/xyz/openbmc_project/software",
                            "xyz.openbmc_project.Control.FieldMode",
                            "FieldModeEnabled", message))
        {
            return 1;
        }

        // Field mode is a boolean type.
        if (auto value = std::get_if<bool>(&message))
        {
            enabled = *value;
        }
        else
        {
            return 1;
        }

        return 0;
    }

    /**
     * Read the ACF replay Id using dbus get properties interface.
     * @brief Read the ACF replay Id.
     *
     * @param replay    The replay Id to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    int readReplayId(uint64_t& replay) const
    {
        PropertyVariant message;

        if (dbusGetProperty(
                "xyz.openbmc_project.Inventory.Manager",
                "/xyz/openbmc_project/inventory/system/chassis/motherboard",
                "com.ibm.ipzvpd.UTIL", "F0", message))
        {
            return 1;
        }

        // Replay id is a vector of bytes.
        uint64_t replayInt = 0;
        if (auto value = std::get_if<std::vector<uint8_t>>(&message))
        {
            // Convert from bytes to int.
            for (auto it = value->rbegin(); it != value->rend(); ++it)
            {
                replayInt = ((replayInt << 8) | (uint64_t)*it);
            }
        }
        else
        {
            return 1;
        }
        replay = replayInt;
        return 0;
    }

    /**
     * Write the ACF replay Id using dbus interface.
     * @brief Write the ACF replay ID.
     *
     * @param replay    The replay Id to write.
     *
     * @return A non-zero error value or zero on success.
     */
    int writeReplayId(uint64_t replay) const
    {
        try
        {
            // Craft the dbus method for writing the replay Id.
            auto bus    = sdbusplus::bus::new_system();
            auto method = bus.new_method_call(
                "com.ibm.VPD.Manager", "/com/ibm/VPD/Manager",
                "com.ibm.VPD.Manager", "WriteKeyword");

            // Convert to bytes.
            std::vector<uint8_t> replayBytes;
            for (size_t i = 0; i < sizeof(replay); ++i)
            {
                replayBytes.push_back((uint8_t)(replay >> (8 * i)));
            }

            // Append the dbus method parameters.
            method.append(static_cast<sdbusplus::message::object_path>(
                              "/xyz/openbmc_project/inventory/system/chassis/"
                              "motherboard"),
                          "UTIL", "F0", replayBytes);

            // Check if dbus method call returned an error.
            auto response = bus.call(method);
            if (response.is_method_error())
            {
                return 1;
            }
        }
        catch (const std::exception& exc)
        {
            return 1;
        }

        return 0;
    }

    /**
     * Unlock a users login acount using dbus interface.
     * @brief Unlock user login account.
     *
     * @param userName  Name of the user account to unlock
     * @param state     State value to set
     *
     * @return A non-zero error value or zero on success.
     */
    int unlockUser(const std::string& userName, bool state = false) const
    {
        // Target the appropriate user
        sdbusplus::message::object_path userPath("/xyz/openbmc_project/user");
        userPath /= userName;
        std::string propertyPath(userPath);

        PropertyVariant message = state;

        // Set the property
        return dbusSetProperty("xyz.openbmc_project.User.Manager", propertyPath,
                               "xyz.openbmc_project.User.Attributes",
                               "UserLockedForFailedAttempt", message);
    }

    /**
     * Enable or disable a users login acount using dbus interface.
     * @brief Enable user login account.
     *
     * @param userName  Name of the user account to enable
     * @param state     State value to set
     *
     * @return A non-zero error value or zero on success.
     */
    int enableUser(const std::string& userName, bool state = true) const
    {
        // Target the appropriate user
        sdbusplus::message::object_path userPath("/xyz/openbmc_project/user");
        userPath /= userName;
        std::string propertyPath(userPath);

        PropertyVariant message = state;

        // Set the property
        return dbusSetProperty("xyz.openbmc_project.User.Manager", propertyPath,
                               "xyz.openbmc_project.User.Attributes",
                               "UserEnabled", message);
    }

    /**
     * Bypass MFA for user login acount using dbus interface.
     * @brief bypass MFA for user login account.
     *
     * @param userName  Name of the user account to bypass MFA
     *
     * @return A non-zero error value or zero on success.
     */
    int bypassMFAUser(const std::string& userName) const
    {
        // Target the appropriate user
        sdbusplus::message::object_path userPath("/xyz/openbmc_project/user");
        userPath /= userName;
        std::string propertyPath(userPath);
        std::string bypassType =
            "xyz.openbmc_project.User.MultiFactorAuthConfiguration.Type."
            "GoogleAuthenticator";
        PropertyVariant message = bypassType;

        // Set the property
        return dbusSetProperty("xyz.openbmc_project.User.Manager", propertyPath,
                               "xyz.openbmc_project.User.TOTPAuthenticator",
                               "BypassedProtocol", message);
    }

    /**
     * Set user privilege level using dbus interface.
     * @brief Set user privilege level.
     *
     * @param userName          Name of the user account to set privilege
     * @param userPrivilege     Privilege value to set
     *
     * @return A non-zero error value or zero on success.
     */
    int userPrivilege(const std::string& userName,
                      const std::string& userPrivilege) const
    {
        // Target the appropriate user
        sdbusplus::message::object_path userPath("/xyz/openbmc_project/user");
        userPath /= userName;
        std::string propertyPath(userPath);

        PropertyVariant message = userPrivilege;

        // Set the property
        return dbusSetProperty("xyz.openbmc_project.User.Manager", propertyPath,
                               "xyz.openbmc_project.User.Attributes",
                               "UserPrivilege", message);
    }

    static int invokeBmcShell(const std::string& shellScript, uint64_t timeout,
                              bool issueBmcDump)
    {
        try
        {
            // Craft the dbus method for invoking the shell script.
            auto bus    = sdbusplus::bus::new_system();
            auto method = bus.new_method_call(
                "xyz.openbmc_project.acfshell", "/xyz/openbmc_project/acfshell",
                "xyz.openbmc_project.TacfShell", "start");
            method.append(shellScript, timeout, issueBmcDump);

            bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            CE_LOG_ERROR("BMC shell invocation failed: ", e.what());
            return 1;
        }
        return 0;
    }
    int initiateResourceDump(const std::string& fileName)
    {
        try
        {
            std::vector<
                std::pair<std::string, std::variant<std::string, uint64_t>>>
                createDumpParams;
            createDumpParams.emplace_back(
                "com.ibm.Dump.Create.CreateParameters.DumpType",
                std::string("com.ibm.Dump.Create.DumpType.Resource"));
            createDumpParams.emplace_back(
                "com.ibm.Dump.Create.CreateParameters.VSPString",
                std::string("TARGETEDACF"));
            createDumpParams.emplace_back(
                "com.ibm.Dump.Create.CreateParameters.Password",
                std::string(""));
            createDumpParams.emplace_back(
                "com.ibm.Dump.Create.CreateParameters.ACFPath", fileName);

            // Craft the dbus method for invoking the shell script.
            auto bus    = sdbusplus::bus::new_system();
            auto method = bus.new_method_call(
                "xyz.openbmc_project.Dump.Manager",
                "/xyz/openbmc_project/dump/system",
                "xyz.openbmc_project.Dump.Create", "CreateDump");
            method.append(createDumpParams);
            bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            CE_LOG_ERROR("Resource dump initiation failed: ", e.what());
            return 1;
        }
        return 0;
    }

    /**
     * Create a new user using dbus interface.
     * @brief Create a user.
     *
     * @param userName      Name of the User to create
     * @param groupNames    Groups to make the user is a member of
     * @param privilege    privilege level of the user
     *
     * @return A non-zero error value or zero on success.
     */
    int createUser(const std::string& userName,
                   const std::vector<std::string> groupNames,
                   const std::string& privilege) const
    {
        auto bus = sdbusplus::bus::new_system();
        try
        {
            // Craft the dbus method for creating the user.
            auto method = bus.new_method_call(
                "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
                "xyz.openbmc_project.User.Manager", "CreateUser");
            method.append(userName, groupNames, privilege, true);

            bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return 1;
        }
        return 0;
    }

  private:
    /**
     * Retrieve a property stored as a dbus property.
     * @brief Retrieve a property.
     *
     * @param service   The service hosting the object and interface.
     * @param path      The path of the dbus object hosting the interface.
     * @param interface The interface for reading the property.
     * @param property  The property to get.
     * @param message   The message returned by the get property method.
     *
     * @return A non-zero error value or zero on success.
     */
    int dbusGetProperty(std::string service, std::string path,
                        std::string interface, std::string property,
                        PropertyVariant& message) const
    {
        try
        {
            // Craft the dbus method for reading the specified property.
            auto bus = sdbusplus::bus::new_default();
            auto method =
                bus.new_method_call(service.c_str(), path.c_str(),
                                    "org.freedesktop.DBus.Properties", "Get");
            method.append(interface, property);

            // Check if dbus method call returned an error.
            auto response = bus.call(method);
            if (response.is_method_error())
            {
                return 1;
            }

            // Retrieve the dbus method response message.
            response.read(message);
        }
        catch (const std::exception& exc)
        {
            return 1;
        }

        return 0;
    }

    /**
     * Write a property stored as a dbus property.
     * @brief Set a property.
     *
     * @param service   Service hosting the object and interface.
     * @param path      Path of the dbus object hosting the interface.
     * @param interface Interface for accessing the property.
     * @param property  Property to access.
     * @param message   Value to set.
     *
     * @return A non-zero error value or zero on success.
     */
    int dbusSetProperty(std::string service, std::string path,
                        std::string interface, std::string property,
                        PropertyVariant& message) const
    {
        try
        {
            // Craft the dbus method for writing the specified property.
            auto bus = sdbusplus::bus::new_system();
            auto method =
                bus.new_method_call(service.c_str(), path.c_str(),
                                    "org.freedesktop.DBus.Properties", "Set");
            method.append(interface.c_str(), property.c_str(), message);

            auto response = bus.call(method);
        }
        catch (const std::exception& e)
        {
            return 1;
        }

        return 0;
    }
};
