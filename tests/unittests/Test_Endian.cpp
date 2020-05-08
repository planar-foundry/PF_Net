#include "UnitTest.hpp"
#include <PF_Net/Endian.hpp>
#include <stdint.h>

PFNET_TEST_CREATE(Endian_Swap)
{
    uint16_t uval16 = 1;
    int16_t val16 = 1;
    uint32_t uval32 = 1;
    int32_t val32 = 1;
    uint64_t uval64 = 1;
    int64_t val64 = 1;

    uint16_t uval16_swapped = PFNET_ENDIAN_SWAP_16(uval16);
    int16_t val16_swapped = PFNET_ENDIAN_SWAP_16(val16);
    uint32_t uval32_swapped = PFNET_ENDIAN_SWAP_32(uval32);
    int32_t val32_swapped = PFNET_ENDIAN_SWAP_32(val32);
    uint64_t uval64_swapped = PFNET_ENDIAN_SWAP_64(uval64);
    int64_t val64_swapped = PFNET_ENDIAN_SWAP_64(val64);

    PFNET_TEST_EXPECT(PFNET_ENDIAN_SWAP_16(uval16_swapped) == uval16);
    PFNET_TEST_EXPECT(PFNET_ENDIAN_SWAP_16(val16_swapped) == val16);
    PFNET_TEST_EXPECT(PFNET_ENDIAN_SWAP_32(uval32_swapped) == uval32);
    PFNET_TEST_EXPECT(PFNET_ENDIAN_SWAP_32(val32_swapped) == val32);
    PFNET_TEST_EXPECT(PFNET_ENDIAN_SWAP_64(uval64_swapped) == uval64);
    PFNET_TEST_EXPECT(PFNET_ENDIAN_SWAP_64(val64_swapped) == val64);
}