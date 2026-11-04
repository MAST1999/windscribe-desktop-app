if(IS_BUILD_TESTS)
    find_package(Boost CONFIG REQUIRED COMPONENTS serialization)
    find_package(skyr-url CONFIG REQUIRED)
    find_package(spdlog CONFIG REQUIRED)
    find_package(re2 CONFIG REQUIRED)

    # Runs the real Utils::executeCommand against /bin/sh, so utils.cpp is compiled in together with the
    # validation code it calls (the helper has no library form).
    add_executable(helperutils.test
        helperutils.test.cpp
        ../utils.cpp
        ../../common/validation_posix.cpp
        ../../../client/client-common/types/ipaddress.cpp
    )
    target_include_directories(helperutils.test PRIVATE
        ../../../client/client-common
    )
    target_link_libraries(helperutils.test PRIVATE
        Boost::serialization
        skyr::skyr-url
        spdlog::spdlog
    )
    set_target_properties(helperutils.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(helperutils)

    find_package(RapidJSON CONFIG REQUIRED)
    add_executable(mainroutetable.test
        mainroutetable.test.cpp
        ../split_tunneling/hostnames_manager/main_route_table.cpp
        ../utils.cpp
        ../../common/validation_posix.cpp
        ../../../client/client-common/types/ipaddress.cpp
    )
    target_include_directories(mainroutetable.test PRIVATE
        ../../../client/client-common
    )
    target_link_libraries(mainroutetable.test PRIVATE
        Boost::serialization
        skyr::skyr-url
        spdlog::spdlog
        rapidjson
    )
    set_target_properties(mainroutetable.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(mainroutetable)

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

    # Regex app-rule matching policy (regex_matching.h); needs only std + RE2.
    add_executable(regexrules.test
        regexrules.test.cpp
    )
    target_link_libraries(regexrules.test PRIVATE
        re2::re2
    )
    set_target_properties(regexrules.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(regexrules)

    # GeoIP country-range loader tests.  country_ranges_loader.cpp needs only std + spdlog.
    add_executable(countryranges.test
        countryranges.test.cpp
        ../split_tunneling/country_ranges_loader.cpp
    )
    target_link_libraries(countryranges.test PRIVATE
        spdlog::spdlog
    )
    set_target_properties(countryranges.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(countryranges)

    # DNS wire-format helpers for the domain-regex resolver.  dns_parse.cpp needs only std.
    add_executable(dnsparsing.test
        dnsparsing.test.cpp
        ../split_tunneling/dns_parse.cpp
    )
    set_target_properties(dnsparsing.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(dnsparsing)

    # Golden tests for the nft command-buffer builders.  Header-only; needs no linking.
    add_executable(nftbuilders.test
        nftbuilders.test.cpp
    )
    set_target_properties(nftbuilders.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(nftbuilders)
endif(IS_BUILD_TESTS)
