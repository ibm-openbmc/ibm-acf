#pragma once

#include <sdbusplus/bus.hpp>

#include <cstdint>
#include <variant>

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
        std::variant<std::string, bool, std::vector<uint8_t>>;

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
        // Craft the dbus method for writing the replay Id.
        auto bus = sdbusplus::bus::new_system();
        auto method =
            bus.new_method_call("com.ibm.VPD.Manager", "/com/ibm/VPD/Manager",
                                "com.ibm.VPD.Manager", "WriteKeyword");

        // Convert to bytes.
        std::vector<uint8_t> replayBytes;
        for (size_t i = 0; i < sizeof(replay); ++i)
        {
            replayBytes.push_back((uint8_t)(replay >> (8 * i)));
        }

        // Append the dbus method parameters.
        method.append(
            static_cast<sdbusplus::message::object_path>(
                "/xyz/openbmc_project/inventory/system/chassis/motherboard"),
            "UTIL", "F0", replayBytes);

        try
        {
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

  private:
    /**
     * Retrieve a property stored as a dbus property.
     * @brief Retrieve a property.
     *
     * @param service   The service hosting the property object and interface.
     * @param path      The path of the dbus object hosting the interface .
     * @param interface The interface for reading the property.
     * @param property  The property to get.
     * @param message   The message returned by the dbus get property method.
     *
     * @return A non-zero error value or zero on success.
     */
    int dbusGetProperty(std::string service, std::string path,
                        std::string interface, std::string property,
                        PropertyVariant& message) const
    {
        // Craft the dbus method for reading the specified property.
        auto bus = sdbusplus::bus::new_default();
        auto method =
            bus.new_method_call(service.c_str(), path.c_str(),
                                "org.freedesktop.DBus.Properties", "Get");
        method.append(interface, property);

        // Try to read the dbus property.
        try
        {
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
};
