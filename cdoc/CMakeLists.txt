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
    $<$<PLATFORM_ID:Windows>:WinBackend.h>
)

add_library(cdoc_obj OBJECT
    CDoc.cpp
    Io.cpp
    Recipient.cpp
    Lock.cpp
    CryptoBackend.cpp
    NetworkBackend.cpp
    PKCS11Backend.cpp
    LogEngine.cpp
    $<$<PLATFORM_ID:Windows>:WinBackend.cpp>
)

if(WIN32)
    add_compile_definitions(UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_compile_options(/GR $<$<CONFIG:Debug>:/JMC>)
endif()

set_target_properties(cdoc_obj PROPERTIES POSITION_INDEPENDENT_CODE YES)
target_compile_definitions(cdoc_obj PRIVATE cdoc_EXPORTS CDOC_DYNAMIC_LINK)
target_include_directories(cdoc_obj PUBLIC ${PROJECT_SOURCE_DIR})
target_link_libraries(cdoc_obj OpenSSL::SSL)

add_library(cdoc_priv OBJECT
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
    Wrapper.h
)

set_property(TARGET cdoc_priv PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(cdoc_priv
    PUBLIC ${PROJECT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(cdoc_priv
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    #$<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
    OpenSSL::SSL
    ZLIB::ZLIB
    LibXml2::LibXml2
    $<$<PLATFORM_ID:Windows>:Crypt32 NCrypt cryptui Bcrypt>
)

add_library(cdoc SHARED ${PUBLIC_HEADERS})
set_target_properties(cdoc PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADERS}"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.cdoc"
    MACOSX_RPATH YES
    COMPILE_DEFINITIONS TARGET_NAME="$<TARGET_NAME:cdoc>"
)
target_link_libraries(cdoc PRIVATE ${CMAKE_DL_LIBS} cdoc_priv cdoc_obj)
target_include_directories(cdoc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_options(cdoc PRIVATE $<$<PLATFORM_ID:Windows>:/SUBSYSTEM:WINDOWS>)

add_library(cdoc_static STATIC ${PUBLIC_HEADERS})
set_target_properties(cdoc_static PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADERS}"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.cdoc"
    MACOSX_RPATH YES
    COMPILE_DEFINITIONS TARGET_NAME="$<TARGET_NAME:cdoc>"
)
target_link_libraries(cdoc_static cdoc_priv cdoc_obj)

add_executable(cdoc-tool cdoc-tool.cpp)
target_link_libraries(cdoc-tool $<IF:$<PLATFORM_ID:Darwin>,cdoc_static,cdoc> cdoc_priv)

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
    target_sources(cdoc_priv PRIVATE ${SCHEMA} ${GENERATED_INCLUDE})
endforeach()

if(SWIG_FOUND)
    include(${SWIG_USE_FILE})
    include_directories(${CMAKE_PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR})
    set_property(SOURCE ../libcdoc.i PROPERTY CPLUSPLUS ON)
    if(JAVA_INCLUDE_PATH)
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/CDocException.java DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/java)
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/IStreamSource.java DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/java)
        set(CMAKE_SWIG_FLAGS -package ee.ria.cdoc)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/java)
        swig_add_library(cdoc_java LANGUAGE java SOURCES ../libcdoc.i)
        target_include_directories(cdoc_java PRIVATE ${JAVA_INCLUDE_PATH} $<$<BOOL:${JAVA_INCLUDE_PATH2}>:${JAVA_INCLUDE_PATH2}>)
        target_compile_definitions(cdoc_java PRIVATE TARGET_NAME="$<TARGET_NAME:cdoc_java>")
        target_link_libraries(cdoc_java cdoc)
        set_target_properties(cdoc_java PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        #install(TARGETS cdoc_java DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_LIBDIR}>) # FIXME: build mac packages
        install(TARGETS cdoc_java DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/java/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ee/ria/cdoc FILES_MATCHING PATTERN "*.java")
        if(WIN32)
            install(FILES $<TARGET_PDB_FILE:cdoc_java> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
        endif()
    endif()
    if(Python3_FOUND)
	# TODO: Fix Python wrapping
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

if(APPLE)
    set(MODULE_LIST ${PUBLIC_HEADERS})
    list(TRANSFORM MODULE_LIST PREPEND "  header \"")
    list(TRANSFORM MODULE_LIST APPEND "\"")
    list(JOIN MODULE_LIST "\n" MODULE_LIST)
    set(MODULE_MAP ${CMAKE_BINARY_DIR}/module.modulemap)
    file(WRITE ${MODULE_MAP} "framework module cdoc {
${MODULE_LIST}
  export *
  requires cplusplus
}")
    target_sources(cdoc PRIVATE ${MODULE_MAP})
    set_source_files_properties(${MODULE_MAP} PROPERTIES MACOSX_PACKAGE_LOCATION Modules)
    if(IOS)
        add_custom_command(TARGET cdoc POST_BUILD
            COMMAND /usr/libexec/PlistBuddy -c "Add :MinimumOSVersion string ${CMAKE_OSX_DEPLOYMENT_TARGET}" $<TARGET_FILE_DIR:cdoc>/Info.plist
        )
    endif()
endif()

install(TARGETS cdoc
    EXPORT cdocExport
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${CDOC_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc
    FRAMEWORK DESTINATION ${FRAMEWORK_DESTINATION}
)

install(TARGETS cdoc_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FRAMEWORK DESTINATION ${FRAMEWORK_DESTINATION}
)

if(NOT ANDROID)
    install(EXPORT cdocExport
        FILE cdoc-config.cmake
        NAMESPACE cdoc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cdoc
    )
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/cdoc-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cdoc-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cdoc
    )
endif()

install( TARGETS cdoc-tool DESTINATION ${CMAKE_INSTALL_BINDIR} )
#install( FILES ${CMAKE_CURRENT_BINARY_DIR}/cdoc-tool.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
#install( FILES ${CMAKE_CURRENT_BINARY_DIR}/libcdoc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig )
