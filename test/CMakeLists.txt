add_executable(unittests
    libcdoc_boost.cpp
    ../cdoc/CDocCipher.cpp
    ../cdoc/Crypto.cpp)

target_link_libraries(unittests
    OpenSSL::SSL
    cdoc
    Boost::unit_test_framework)

add_test(NAME runtest
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/unittests --build_info=YES --logger=HRF,all,stdout
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test
)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS unittests)
