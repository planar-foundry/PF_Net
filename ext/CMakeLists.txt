if (NOT TARGET PF_Debug)
    add_subdirectory(PF_Debug)
endif()

if (NOT TARGET PF_Endian)
    add_subdirectory(PF_Endian)
endif()

if (NOT TARGET PF_Test AND ${PFNET_BUILD_TESTS})
    add_subdirectory(PF_Test)
endif()
