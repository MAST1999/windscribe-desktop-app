if(IS_BUILD_TESTS)
    # The wine/Proton path-matching regression tests.  path_matching.h is dependency-free,
    # so the test needs no linking.
    add_executable(pathmatching.test
        pathmatching.test.cpp
    )
    target_include_directories(pathmatching.test PRIVATE
        ..
    )
    set_target_properties(pathmatching.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(pathmatching)
endif(IS_BUILD_TESTS)
