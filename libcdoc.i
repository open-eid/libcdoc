%module cdoc

%{
#include "libcdoc/Io.h"
#include "libcdoc/Configuration.h"
#include "libcdoc/Lock.h"
#include "libcdoc/CDocWriter.h"
#include "libcdoc/CDocReader.h"
%}

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
//%include "std_map.i"

%include "typemaps.i"

#ifdef SWIGJAVA
%typemap(in) (const uint8_t *src, size_t size) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(freearg) (const uint8_t *src, size_t size) %{
    jenv->ReleaseByteArrayElements($input, (jbyte *) $1, JNI_ABORT);
%}
%typemap(out) (const uint8_t *src, size_t size) %{
    jresult = jenv->NewByteArray(size);
%}
%typemap(jni) (const uint8_t *src, size_t size) "jbyteArray"
%typemap(jtype) (const uint8_t *src, size_t size) "jbyteArray"
%typemap(jstype) (const uint8_t *src, size_t size) "byte[]"

%typemap(in) std::vector<uint8_t> %{
    jbyte *$input_ptr = jenv->GetByteArrayElements($input, NULL);
    jsize $input_size = jenv->GetArrayLength($input);
    std::vector<uint8_t> $1_data($input_ptr, $input_ptr+$input_size);
    $1 = $1_data;
    jenv->ReleaseByteArrayElements($input, $input_ptr, JNI_ABORT);
%}
%typemap(out) std::vector<uint8_t> %{
    jresult = jenv->NewByteArray((&result)->size());
    jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte*)(&result)->data());
%}
%typemap(jtype) const std::vector<uint8_t>& "byte[]"
%typemap(jstype) const std::vector<uint8_t>& "byte[]"
%typemap(jni) std::vector<uint8_t> "jbyteArray"
%typemap(javain) std::vector<uint8_t> "$javainput"
%typemap(javaout) std::vector<uint8_t> {
    return $jnicall;
  }
#endif

// Swig does not like visibility/declspec attributes
#define CDOC_EXPORT

%include "Io.h"
%include "Configuration.h"
%include "CryptoBackend.h"
%include "NetworkBackend.h"
%include "Lock.h"
%include "CDocReader.h"
%include "CDocWriter.h"
