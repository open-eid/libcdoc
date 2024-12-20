set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

add_executable(unittests libcdoc_boost.cpp)
target_link_libraries(unittests cdoc cdoc_priv Boost::unit_test_framework)

add_test(NAME runtest
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/unittests --build_info=YES --logger=HRF,all,stdout -- ${CMAKE_CURRENT_SOURCE_DIR}/data
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS unittests)
