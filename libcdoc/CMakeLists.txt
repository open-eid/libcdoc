set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

set(SCHEMAS
        schema/recipients.fbs
        schema/header.fbs
)

set(PUBLIC_HEADERS
    CDoc.h
    CDocReader.h
    CDocWriter.h
    Configuration.h
    Io.h
    Recipient.h
    Lock.h
    CryptoBackend.h
    NetworkBackend.h
)

set(CDOC_SOURCES
    CDoc.cpp
    Io.cpp
    Recipient.cpp
    Lock.cpp
    CryptoBackend.cpp
)

add_library(cdoc_obj OBJECT
    ${CDOC_SOURCES}
)

set_property(TARGET cdoc_obj PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(cdoc_obj PUBLIC
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(CDOC_PRIV_SOURCES
    Certificate.cpp
    Crypto.cpp
    Tar.cpp
    XMLReader.cpp
    XMLWriter.cpp
    ZStream.cpp
    Utils.cpp
    CDoc1Reader.cpp
    CDoc1Writer.cpp
    CDoc2Reader.cpp
    CDoc2Writer.cpp
    DDocReader.cpp
    DDocWriter.cpp
    XmlReader.cpp XmlReader.h
    XMLWriter.cpp XmlWriter.h
)

add_library(cdoc_priv_obj OBJECT
    ${CDOC_PRIV_SOURCES}
)

set_property(TARGET cdoc_priv_obj PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(cdoc_priv_obj PUBLIC
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(cdoc_priv_obj
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
)

add_library(cdoc_priv STATIC
    $<TARGET_OBJECTS:cdoc_priv_obj>
)

set_property(TARGET cdoc_priv PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(cdoc_priv PUBLIC
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(cdoc_priv
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
    ${ZLIB_LIBRARY}
    ${LIBXML2_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${LIBS}
)

add_library(cdoc SHARED
    ${PUBLIC_HEADERS}
    $<TARGET_OBJECTS:cdoc_obj>
)

set_target_properties(cdoc PROPERTIES
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_RPATH YES
    COMPILE_DEFINITIONS TARGET_NAME="$<TARGET_NAME:cdoc>"
)

target_include_directories(cdoc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(cdoc PRIVATE
    ${CMAKE_DL_LIBS}
    cdoc_priv
)

add_library(cdoc_static STATIC
    ${PUBLIC_HEADERS}
    $<TARGET_OBJECTS:cdoc_priv_obj>
    $<TARGET_OBJECTS:cdoc_obj>
)

set_target_properties(cdoc_static PROPERTIES
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_RPATH YES
    COMPILE_DEFINITIONS TARGET_NAME="$<TARGET_NAME:cdoc>"
)

target_include_directories(cdoc_static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(cdoc_static
    ${ZLIB_LIBRARY}
    ${LIBXML2_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${LIBS}
)

foreach(SCHEMA ${SCHEMAS})
        get_filename_component(stem ${SCHEMA} NAME_WE)
        get_filename_component(name ${SCHEMA} NAME)
        set(GENERATED_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/${stem}_generated.h)
        add_custom_command(
                OUTPUT ${GENERATED_INCLUDE}
                COMMENT "Compiling flatbuffer for ${name}"
                COMMAND flatbuffers::flatc
                        --cpp
                        --scoped-enums
                        -o ${CMAKE_CURRENT_BINARY_DIR}
                        -I ${CMAKE_CURRENT_SOURCE_DIR}
                        ${SCHEMA}
                DEPENDS flatbuffers::flatc ${SCHEMA}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        target_sources(cdoc_priv_obj PRIVATE ${SCHEMA} ${GENERATED_INCLUDE})
endforeach()

install(TARGETS cdoc
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${DIGIDOCPP_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc
    FRAMEWORK DESTINATION /Library/Frameworks
)

