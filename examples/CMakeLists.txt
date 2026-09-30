# Java example (CDocTool) built with the Gradle wrapper in examples/java.
#
# The example compiles against the SWIG-generated Java bindings produced by
# the cdoc_java target. It is added to the default build only when:
#   * SWIG was found and the cdoc_java target exists, and
#   * a Java Development Kit was found (Java_Development_FOUND), and
#   * the Gradle wrapper script is present in the source tree, and
#   * LIBCDOC_BUILD_JAVA_EXAMPLE is ON (default).
#
# The Gradle invocation is given absolute paths to the SWIG Java sources and
# the JNI library of the current build, so no manual configuration is needed.

set(JAVA_EXAMPLE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/java)

if(WIN32)
    set(GRADLE_WRAPPER ${JAVA_EXAMPLE_DIR}/gradlew.bat)
else()
    set(GRADLE_WRAPPER ${JAVA_EXAMPLE_DIR}/gradlew)
endif()

if(NOT EXISTS ${GRADLE_WRAPPER})
    message(STATUS "Gradle wrapper not found in ${JAVA_EXAMPLE_DIR} - skipping Java example")
    return()
endif()

if(NOT TARGET cdoc_java)
    message(STATUS "cdoc_java target not available - skipping Java example")
    return()
endif()

if(NOT Java_Development_FOUND)
    message(STATUS "Java Development Kit not found - skipping Java example")
    return()
endif()

option(LIBCDOC_BUILD_JAVA_EXAMPLE "Build the Java CDocTool example with Gradle" ON)
if(NOT LIBCDOC_BUILD_JAVA_EXAMPLE)
    return()
endif()

# Directory containing the SWIG-generated .java files (OUTPUT_DIR of
# swig_add_library in cdoc/CMakeLists.txt). CDOC_BINARY_DIR is set by the
# parent CMakeLists.txt right after add_subdirectory(cdoc); fall back to the
# conventional location if this file is used standalone.
if(NOT CDOC_BINARY_DIR)
    set(CDOC_BINARY_DIR ${CMAKE_BINARY_DIR}/cdoc)
endif()
set(JAVA_EXAMPLE_SWIG_DIR ${CDOC_BINARY_DIR}/java)
set(JAVA_EXAMPLE_JAR ${JAVA_EXAMPLE_DIR}/build/libs/CDocTool.jar)

add_custom_command(
    OUTPUT ${JAVA_EXAMPLE_JAR}
    COMMENT "Building and testing Java example (CDocTool.jar) with Gradle"
    COMMAND ${GRADLE_WRAPPER}
            --no-daemon
            --quiet
            -PswigJavaDir=${JAVA_EXAMPLE_SWIG_DIR}
            -PjniLibDir=$<TARGET_FILE_DIR:cdoc_java>
            build
    WORKING_DIRECTORY ${JAVA_EXAMPLE_DIR}
    DEPENDS cdoc_java
    VERBATIM
)

add_custom_target(cdoc_java_example ALL
    DEPENDS ${JAVA_EXAMPLE_JAR}
)
