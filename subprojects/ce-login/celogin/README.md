# README

Note: all code within this directory/any subdirectories needs to conform to the C++97 standard.
This is because this code is used in the PowerVM adjunct environment. There are still Power
firmware releases in support that use a compiler that expects C++97 conformant code. If this
requirement is lifted in the future, this README will be updated. Note that if there are changes
that require functionality from a newer standard that are desired for BMC/CLI functionality
(see include/ce_logger.hpp for an example), the CELOGIN_POWERVM_TARGET define can be used
to scope this code so as to not break compatibility with the PowerVM adjunct environment.