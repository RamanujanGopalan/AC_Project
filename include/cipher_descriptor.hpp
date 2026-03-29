#pragma once

#include <cstddef>

struct CipherDescriptor {
    const char *name;
    const char *variant;
    size_t block_size_bytes;
};
