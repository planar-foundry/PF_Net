#pragma once

#include <PF_Test/UnitTest.hpp>
#include <stdint.h>

// This is necessary because on some Linux systems it is not possible to rebind a port you just
// used without setting some socket options which I don't want to code cross platform support for.
uint16_t get_unique_port();
