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
    Exports.h
    Io.h
    Recipient.h
    Lock.h
    CryptoBackend.h
    NetworkBackend.h
    PKCS11Backend.h
    ILogger.h
    ConsoleLogger.h
)

set(CDOC_SOURCES
    CDoc.cpp
    Io.cpp
    Recipient.cpp
    Lock.cpp
    CryptoBackend.cpp
    NetworkBackend.cpp
    PKCS11Backend.cpp
    LogEngine.cpp
)

add_library(cdoc_obj OBJECT
    ${CDOC_SOURCES}
)

set_target_properties(cdoc_obj PROPERTIES
    COMPILE_DEFINITIONS cdoc_EXPORTS
    POSITION_INDEPENDENT_CODE YES
)

target_include_directories(cdoc_obj PUBLIC
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(CDOC_PRIV_SOURCES
    Certificate.cpp Certificate.h
    Crypto.cpp Crypto.h
    Tar.cpp
    ZStream.cpp
    Utils.cpp Utils.h
    CDoc1Reader.cpp
    CDoc1Writer.cpp
    CDoc2Reader.cpp
    CDoc2Writer.cpp
    DDocReader.cpp
    DDocWriter.cpp
    XmlReader.cpp XmlReader.h
    XmlWriter.cpp XmlWriter.h
    CDocChipher.h CDocChipher.cpp
    RcptInfo.h
    ToolConf.h
    CDoc2.h
)

add_library(cdoc_priv_obj OBJECT
    ${CDOC_PRIV_SOURCES}
)

set_property(TARGET cdoc_priv_obj PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(cdoc_priv_obj PUBLIC
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(cdoc_priv_obj
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
    OpenSSL::SSL
)

if (WIN32)
    target_link_libraries(cdoc_priv_obj Bcrypt.lib)
endif()

add_library(cdoc_priv STATIC
    $<TARGET_OBJECTS:cdoc_priv_obj>
    Wrapper.h
)

set_property(TARGET cdoc_priv PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(cdoc_priv PUBLIC
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(cdoc_priv
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
    ZLIB::ZLIB
#    {$ZLIB_LIBRARIES}
    LibXml2::LibXml2
    OpenSSL::SSL
    ${LIBS}
)

add_library(cdoc SHARED
    ${PUBLIC_HEADERS}
    ${CDOC_SOURCES}

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
    ${PROJECT_SOURCE_DIR}
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

add_executable(cdoc-tool cdoc-tool.cpp)

target_link_libraries(cdoc-tool cdoc cdoc_priv)

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

if(SWIG_FOUND)
    include(${SWIG_USE_FILE})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    set_property(SOURCE ../libcdoc.i PROPERTY CPLUSPLUS ON)
    if(JAVA_INCLUDE_PATH)
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/CDocException.java DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/java)
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/IStreamSource.java DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/java)
        set(CMAKE_SWIG_FLAGS -package ee.ria.libcdoc)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/java)
        swig_add_library(cdoc_java LANGUAGE java SOURCES ../libcdoc.i)
        target_include_directories(cdoc_java PRIVATE ${JAVA_INCLUDE_PATH} $<$<BOOL:${JAVA_INCLUDE_PATH2}>:${JAVA_INCLUDE_PATH2}>)
        target_compile_definitions(cdoc_java PRIVATE TARGET_NAME="$<TARGET_NAME:cdoc_java>")
        target_link_libraries(cdoc_java cdoc)
        set_target_properties(cdoc_java PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        install(TARGETS cdoc_java DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_LIBDIR}>)
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/java/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ee/ria/libcdoc FILES_MATCHING PATTERN "*.java")
        if(WIN32)
            install(FILES $<TARGET_PDB_FILE:cdoc_java> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
        endif()
    endif()
    if(Python3_FOUND)
        # -py3 option is removed starting from SWIG-4.1.0
        set(CMAKE_SWIG_FLAGS -py3)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})
        swig_add_library(cdoc_python LANGUAGE python SOURCES ../libcdoc.i)
        target_compile_definitions(cdoc_python PRIVATE TARGET_NAME="$<TARGET_NAME:cdoc_python>")
        target_link_libraries(cdoc_python cdoc Python3::Module)
        #configure_file(setup.py.cmake setup.py)
        #install(CODE "execute_process(COMMAND python3 ${CMAKE_CURRENT_BINARY_DIR}/setup.py install)")
        if(NOT Python3_SITELIB)
            execute_process(COMMAND /usr/bin/python3 -c
                "from distutils import sysconfig;print(sysconfig.get_python_lib(plat_specific=False,standard_lib=False))"
                OUTPUT_VARIABLE Python3_SITELIB OUTPUT_STRIP_TRAILING_WHITESPACE)
        endif()
        if(WIN32)
            set(Python3_SITELIB ${CMAKE_INSTALL_BINDIR})
            install(FILES $<TARGET_PDB_FILE:cdoc_python> DESTINATION ${Python3_SITELIB} OPTIONAL)
        else()
            set_target_properties(cdoc_python PROPERTIES SUFFIX .so)
        endif()
        set_target_properties(cdoc_python PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        install(TARGETS cdoc_python DESTINATION ${Python3_SITELIB})
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cdoc.py DESTINATION ${Python3_SITELIB})
    endif()

    set(CMAKE_SWIG_FLAGS -dllimport cdoc_csharp -namespace cdoc)
    set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
    swig_add_library(cdoc_csharp LANGUAGE csharp SOURCES ../libcdoc.i)
    target_compile_definitions(cdoc_csharp PRIVATE TARGET_NAME="$<TARGET_NAME:cdoc_csharp>")
    target_link_libraries(cdoc_csharp cdoc)
    set_target_properties(cdoc_csharp PROPERTIES
        SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
        PREFIX "${CMAKE_SHARED_LIBRARY_PREFIX}"
    )
    install(TARGETS cdoc_csharp DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc_csharp FILES_MATCHING PATTERN "*.cs")
    if(WIN32)
        install(FILES $<TARGET_PDB_FILE:cdoc_csharp> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
    endif()
endif()

install(TARGETS cdoc
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${CDOC_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc
    FRAMEWORK DESTINATION /Library/Frameworks
)

