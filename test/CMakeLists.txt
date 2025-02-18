add_executable(unittests libcdoc_boost.cpp ../cdoc/CDocChipher.cpp)
target_compile_definitions(unittests PRIVATE DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(unittests OpenSSL::SSL cdoc Boost::unit_test_framework)

add_test(NAME runtest
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/unittests --build_info=YES --logger=HRF,all,stdout
    WORKING_DIRECTORY $<TARGET_FILE_DIR:cdoc>
)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS unittests)
