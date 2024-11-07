%module(directors="1") cdoc

%{
#include "libcdoc/Io.h"
#include "libcdoc/Configuration.h"
#include "libcdoc/Lock.h"
#include "libcdoc/CDocWriter.h"
#include "libcdoc/CDocReader.h"
#include "libcdoc/Recipient.h"
%}

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
//%include "std_map.i"

%include "typemaps.i"

#ifdef SWIGJAVA
%include "arrays_java.i"
%include "enums.swg"
%javaconst(1);
%apply long long { int64_t }
%apply int { int32_t }

// CDocWriter
%ignore libcdoc::CDocWriter::createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
%ignore libcdoc::CDocWriter::encrypt(MultiDataSource& src, const std::vector<libcdoc::Recipient>& recipients);
// int64_t write(cont uint8_t *src, size_t pos, size_t len) -> long read(byte[] src, long pos, long len)
%extend libcdoc::CDocWriter {
    int64_t writeData(const uint8_t *src, size_t pos, size_t size) {
        return $self->writeData(src + pos, size);
    }
};
%typemap(in) (const uint8_t *src) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
%}
%typemap(javain) const uint8_t *src "$javainput"
%typemap(jni) const uint8_t *src "jbyteArray"
%typemap(jtype) const uint8_t *src "byte[]"
%typemap(jstype) const uint8_t *src "byte[]"

// int64_t write(const uint8_t *src, size_t len) -> long read(byte[] src)
%typemap(in) (const uint8_t *src, size_t size) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(javain) (const uint8_t *src, size_t size) "$javainput"
%typemap(jni) (const uint8_t *src, size_t size) "jbyteArray"
%typemap(jtype) (const uint8_t *src, size_t size) "byte[]"
%typemap(jstype) (const uint8_t *src, size_t size) "byte[]"

// CDocReader
// Use LockVector object to encapsulate the vector of locks
%template(LockVector) std::vector<libcdoc::Lock>;
// Custom wrapper do away with cont qualifiers
%extend libcdoc::CDocReader {
    std::vector<libcdoc::Lock> getLocks() {
        static const std::vector<const libcdoc::Lock> locks = $self->getLocks();
        std::vector<libcdoc::Lock> p(locks.cbegin(), locks.cend());
        return std::move(p);
    }
};
%ignore libcdoc::CDocReader::getLocks();
// int64_t read(uint8_t *dst, size_t const ssize)
%typemap(in) (uint8_t *dst, size_t size) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(freearg) (uint8_t *dst, size_t size) %{
    jenv->ReleaseByteArrayElements($input, (jbyte *) $1, 0);
%}
%typemap(javain) (uint8_t *dst, size_t size) "$javainput"
%typemap(jni) (uint8_t *dst, size_t size) "jbyteArray"
%typemap(jtype) (uint8_t *dst, size_t size) "byte[]"
%typemap(jstype) (uint8_t *dst, size_t size) "byte[]"

// Lock
%ignore libcdoc::Lock::Lock;
%ignore libcdoc::Lock::type;
%ignore libcdoc::Lock::pk_type;
%ignore libcdoc::Lock::label;
%ignore libcdoc::Lock::encrypted_fmk;
%ignore libcdoc::Lock::setBytes;
%ignore libcdoc::Lock::setString;
%ignore libcdoc::Lock::setInt;
%ignore libcdoc::Lock::setCertificate;
%extend libcdoc::Lock {
    Type getType() {
        return $self->type;
    }
    PKType getPKType() {
        return $self->pk_type;
    }
    std::string getLabel() {
        return $self->label;
    }
    std::vector<uint8_t> getEncryptedFMK() {
        return $self->encrypted_fmk;
    }
}

// DataSource
%ignore libcdoc::DataConsumer::write(const std::vector<uint8_t>& src);
%ignore libcdoc::DataConsumer::write(const std::string& str);

#if 0
%typemap(in) (std::vector<uint8_t>& dst) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(javain) (std::vector<uint8_t>& dst) "$javainput"
%typemap(jni) (std::vector<uint8_t>& dst) "jbyteArray"
%typemap(jtype) (std::vector<uint8_t>& dst) "byte[]"
%typemap(jstype) (std::vector<uint8_t>& dst) "byte[]"

%extend libcdoc::CDocReader {
    std::vector<uint8_t> readData(size_t size) {
        std::vector<uint8_t> tmp(size);
        $self->readData(tmp.data(), size);
        return std::move(tmp);
    }
};
#endif

%typemap(out) std::vector<uint8_t> %{
    jresult = jenv->NewByteArray((&result)->size());
    jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte*)(&result)->data());
%}
%typemap(jtype) std::vector<uint8_t> "byte[]"
%typemap(jstype) std::vector<uint8_t> "byte[]"
%typemap(jni) std::vector<uint8_t> "jbyteArray"
%typemap(javaout) std::vector<uint8_t> {
    return $jnicall;
}

%typemap(in) (std::vector<uint8_t>& dst) %{
    jsize $input_size = jenv->GetArrayLength($input);
    std::vector<uint8_t> $1_data($input_size);
    $1 = &$1_data;
%}
%typemap(freearg) (std::vector<uint8_t>& dst) %{
    jenv->SetByteArrayRegion($input, 0, $1_data.size(), (const jbyte*) $1_data.data());
%}
%typemap(out) std::vector<uint8_t>& %{
    jresult = jenv->NewByteArray((&result)->size());
    jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte*)(&result)->data());
%}
%typemap(jtype) std::vector<uint8_t>& "byte[]"
%typemap(jstype) std::vector<uint8_t>& "byte[]"
%typemap(jni) std::vector<uint8_t>& "jbyteArray"
%typemap(javaout) std::vector<uint8_t>& {
    return $jnicall;
}

%typemap(out) std::string_view %{
    std::string tmp(result.cbegin(), result.cend());
    jresult = jenv->NewStringUTF(tmp.c_str());
%}
%typemap(jtype) std::string_view "String"
%typemap(jstype) std::string_view "String"
%typemap(jni) std::string_view "jstring"
%typemap(javaout) std::string_view {
    return $jnicall;
}

%feature("director") CryptoBackend;

#endif

// Swig does not like visibility/declspec attributes
#define CDOC_EXPORT

%include "CDoc.h"
%include "Io.h"
%include "Configuration.h"
%include "CryptoBackend.h"
%include "NetworkBackend.h"
%include "Lock.h"
%include "Recipient.h"
%include "CDocReader.h"
%include "CDocWriter.h"

#ifdef SWIGJAVA
#endif
