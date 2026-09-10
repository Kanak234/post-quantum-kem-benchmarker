#pragma once

#include "params.hpp"

namespace kem {

int16_t montgomery_reduce(int32_t a);
int16_t barrett_reduce(int16_t a);
int16_t fqmul(int16_t a, int16_t b);

} // namespace kem
