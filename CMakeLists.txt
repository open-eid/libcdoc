cmake_minimum_required(VERSION 3.21)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

project(libcdoc VERSION 0.1.1)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

include(VersionInfo)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_DEBUG_POSTFIX "d" CACHE STRING "Adds a postfix for debug-built libraries.")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR RPM)
set(CPACK_PACKAGE_CONTACT "RIA <info@ria.ee>")
set(CPACK_PACKAGE_VENDOR RIA)
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
list(APPEND CPACK_RPM_RELOCATION_PATHS ${CMAKE_INSTALL_SYSCONFDIR})
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
include(CPack)

find_package(Doxygen)
find_package(OpenSSL 3.0.0 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(FlatBuffers CONFIG REQUIRED NAMES FlatBuffers Flatbuffers)
find_package(SWIG)
find_package(JNI)
find_package(Python3 COMPONENTS Interpreter Development)

if( DOXYGEN_FOUND )
    configure_file(${CMAKE_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
    add_custom_target(docs ALL
        Doxygen::doxygen Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    install(DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
    install(DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
endif()

if( WIN32 )
    add_definitions( -DUNICODE -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN )
endif()

enable_testing()
add_subdirectory(libcdoc)

find_package(Boost COMPONENTS unit_test_framework QUIET)
if (TARGET Boost::unit_test_framework)
    add_subdirectory(test)
endif()
