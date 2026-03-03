prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_FULL_BINDIR@
libdir=@CMAKE_INSTALL_FULL_LIBDIR@
includedir=@CMAKE_INSTALL_FULL_INCLUDEDIR@

Name: libcdoc
Description: Libcdoc C++ library for creating/decrypting CDoc containers
Version: @PROJECT_VERSION@
Libs: -L${libdir} -lcdoc
Cflags: -I${includedir}
