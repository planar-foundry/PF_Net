if (NOT TARGET PF_Debug)
    add_subdirectory(PF_Debug)
endif()

if (NOT TARGET PF_Streams)
    add_subdirectory(PF_Streams)
endif()

if (NOT TARGET PF_Test AND ${PFNET_BUILD_TESTS})
    add_subdirectory(PF_Test)
endif()
