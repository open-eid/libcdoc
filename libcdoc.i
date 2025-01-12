%module(directors="1") CDoc

%{
#include "libcdoc/Io.h"
#include "libcdoc/Configuration.h"
#include "libcdoc/Lock.h"
#include "libcdoc/CDocWriter.h"
#include "libcdoc/CDocReader.h"
#include "libcdoc/Utils.h"
#include "libcdoc/Wrapper.h"
#include <iostream>
%}

// Handle standard C++ types
%include "std_string.i"
%include "std_vector.i"
//%include "std_map.i"

%include "typemaps.i"

%ignore libcdoc::ChainedConsumer;
%ignore libcdoc::ChainedSource;
%ignore libcdoc::IStreamSource;
%ignore libcdoc::OStreamConsumer;
%ignore libcdoc::VectorConsumer;
%ignore libcdoc::VectorSource;
%ignore libcdoc::FileListConsumer;
%ignore libcdoc::FileListSource;

%ignore libcdoc::CDocWriter::createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
%ignore libcdoc::CDocWriter::createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
%ignore libcdoc::CDocWriter::encrypt(MultiDataSource& src, const std::vector<libcdoc::Recipient>& recipients);

%ignore libcdoc::CDocReader::getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock& lock);
%ignore libcdoc::CDocReader::nextFile(std::string& name, int64_t& size);
%ignore libcdoc::CDocReader::getLockForCert(Lock& lock, const std::vector<uint8_t>& cert);
%ignore libcdoc::CDocReader::decrypt(const std::vector<uint8_t>& fmk, MultiDataConsumer *consumer);

#ifdef SWIGJAVA
%include "arrays_java.i"
%include "enums.swg"
%javaconst(1);
%apply long long { int64_t }
%apply long long { uint64_t }
%apply int { int32_t }

//
// std::vector<uint8_t> <- byte[]
//

%typemap(out) std::vector<uint8_t> %{
    // std::vector<uint8_t> out
    jresult = jenv->NewByteArray((&result)->size());
    jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte*)(&result)->data());
%}
%typemap(in) std::vector<uint8_t> %{
    // std::vector<uint8_t> in
%}
%typemap(jtype) std::vector<uint8_t> "byte[]"
%typemap(jstype) std::vector<uint8_t> "byte[]"
%typemap(jni) std::vector<uint8_t> "jbyteArray"
%typemap(javaout) std::vector<uint8_t> {
    return $jnicall;
}

%ignore libcdoc::DataBuffer::data;
%ignore libcdoc::DataBuffer::DataBuffer(std::vector<uint8_t> *_data);

//
// std::vector<uint8_t>& -> byte[]
//

%typemap(in) (std::vector<uint8_t>&) %{
    // std::vector<uint8_t>& in
    jsize $input_size = jenv->GetArrayLength($input);
    uint8_t *$input_data = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    std::vector<uint8_t> $1_vec($input_data, $input_data + $input_size);
    $1 = &$1_vec;

%}
%typemap(freearg) (std::vector<uint8_t>&) %{
    // std::vector<uint8_t>& freearg
    jenv->ReleaseByteArrayElements($input, (jbyte *) $input_data, 0);
%}
%typemap(out) std::vector<uint8_t>& %{
    // std::vector<uint8_t>& out
    jresult = jenv->NewByteArray(result->size());
    jenv->SetByteArrayRegion(jresult, 0, result->size(), (const jbyte*)result->data());
%}
%typemap(jtype) std::vector<uint8_t>& "byte[]"
%typemap(jstype) std::vector<uint8_t>& "byte[]"
%typemap(jni) std::vector<uint8_t>& "jbyteArray"
%typemap(javain) std::vector<uint8_t>& "$javainput"
%typemap(javaout) std::vector<uint8_t>& {
    return $jnicall;
}
%typemap(directorin,descriptor="[B") std::vector<uint8_t>& %{
    $input = jenv->NewByteArray($1.size());
    jenv->SetByteArrayRegion($input, 0, $1.size(), (const jbyte*)$1.data());
%}
%typemap(javadirectorin) std::vector<uint8_t>& "$jniinput"

//
// std::vector<uint8_t>& dst <-> DataBuffer
//

%typemap(out) std::vector<uint8_t>& dst %{
    int kalakala_out = 1;
    *(libcdoc::Lock **)&jlock = (libcdoc::Lock *) &lock;
%}
%typemap(freearg) std::vector<uint8_t>& dst %{
    // DataBuffer freearg
%}
%typemap(in) std::vector<uint8_t>& dst %{
    jclass conf_class = jenv->FindClass("ee/ria/libcdoc/Configuration");
    jmethodID mid = jenv->GetStaticMethodID(conf_class, "getCPtr", "(Lee/ria/libcdoc/Configuration;)J");
    jlong cptr = jenv->CallStaticLongMethod(conf_class, mid, $input);
    libcdoc::DataBuffer *db = (libcdoc::DataBuffer *) cptr;
    $1 = db->data;
%}
%typemap(jtype) std::vector<uint8_t>& dst "DataBuffer"
%typemap(jstype) std::vector<uint8_t>& dst "DataBuffer"
%typemap(jni) std::vector<uint8_t>& dst "jobject"
%typemap(javaout) std::vector<uint8_t>& dst "$jnicall"
%typemap(javain) std::vector<uint8_t>& dst "$javainput"
%typemap(directorin,descriptor="Lee/ria/libcdoc/DataBuffer;") std::vector<uint8_t>& dst %{
    libcdoc::DataBuffer $1_db(&$1);
    jclass buf_class = jenv->FindClass("ee/ria/libcdoc/DataBuffer");
    jmethodID mid = jenv->GetMethodID(buf_class, "<init>", "(JZ)V");
    jobject obj = jenv->NewObject(buf_class, mid, (jlong) &$1_db, (jboolean) 0);
    $input = obj;
%}
%typemap(javadirectorin) std::vector<uint8_t>& dst "$jniinput"

//
// std::string_view& -> String
//

%typemap(in) std::string_view& %{
    const char *$1_utf8 = jenv->GetStringUTFChars($input, nullptr);
    std::string_view $1_sv($1_utf8);
    $1 = &$1_sv;
%}
%typemap(freearg) std::string_view& %{
    jenv->ReleaseStringUTFChars($input, $1_utf8);
%}
//%typemap(out) std::string_view& %{
//    std::string $1_str(*(&result));
//    jresult = jenv->NewStringUtf($1_str.c_str());
//%}
%typemap(jtype) std::string_view& "String"
%typemap(jstype) std::string_view& "String"
%typemap(jni) std::string_view& "jstring"
%typemap(javain) std::string_view& "$javainput"
//%typemap(javaout) std::string_view& %{
//    return $jnicall;
//%}
%typemap(directorin,descriptor="Ljava/lang/String;") std::string_view& %{
    std::string $1_str($1);
    $input = jenv->NewStringUTF($1_str.c_str());
%}
// No return of std::string_view& so no directorout
%typemap(javadirectorin) std::string_view& "$jniinput"
// No return of std::string_view& so no javadirectorout

//
// CDocWriter
//


// int64_t write(cont uint8_t *src, size_t pos, size_t len) -> long read(byte[] src, long pos, long len)
%extend libcdoc::CDocWriter {
    int64_t writeData(const uint8_t *src, size_t pos, size_t size) {
        return $self->writeData(src + pos, size);
    }
};

//
// const uint8_t *src -> byte[]
//

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

// MultiDataSource
%ignore libcdoc::MultiDataSource::next(std::string& name, int64_t& size);

//
// CDocReader
//

// Use LockVector object to encapsulate the vector of locks
%template(LockVector) std::vector<libcdoc::Lock>;
// Custom wrapper do away with const qualifiers
%extend libcdoc::CDocReader {
    std::vector<libcdoc::Lock> getLocks() {
        static const std::vector<const libcdoc::Lock> locks = $self->getLocks();
        std::vector<libcdoc::Lock> p(locks.cbegin(), locks.cend());
        return std::move(p);
    }
    libcdoc::Lock getLockForCert(const std::vector<uint8_t>& cert) {
        libcdoc::Lock lock;
        $self->getLockForCert(lock, cert);
        return lock;
    }
    std::vector<uint8_t> getFMK(const libcdoc::Lock& lock) {
        std::vector<uint8_t> fmk;
        $self->getFMK(fmk, lock);
        return fmk;
    }
};
%ignore libcdoc::CDocReader::getLocks();

%typemap(javaimports) libcdoc::CDocReader %{
    import java.io.IOException;
    import java.io.OutputStream;
%}

%typemap(javacode) libcdoc::CDocReader %{
    public void readFile(OutputStream ofs) throws IOException {
        byte[] buf = new byte[1024];
        long result = readData(buf);
        while(result > 0) {
            ofs.write(buf, 0, (int) result);
            result = readData(buf);
        }
    }
%}

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

// Recipient
%ignore libcdoc::Recipient::rcpt_key;
%ignore libcdoc::Recipient::cert;
%extend libcdoc::Recipient {
    std::vector<uint8_t> getRcptKey() {
        return $self->rcpt_key;
    }
    void setRcptKey(const std::vector<uint8_t>& key) {
        $self->rcpt_key = key;
    }
    std::vector<uint8_t> getCert() {
        return $self->cert;
    }
    void setCert(const std::vector<uint8_t>& value) {
        $self->cert = value;
    }
};

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

//
// std::vector<std::vector<uint8_t>> <- byte[][]
//

// C -> JNI
%typemap(out) std::vector<std::vector<uint8_t>> %{
    // byte[] class
    jclass cls = jenv->FindClass("[B");
    jresult = jenv->NewObjectArray((&result)->size(), cls, nullptr);
    for (size_t i = 0; i < (&result)->size(); i++) {
        const std::vector<uint8_t>& ch = (&result)->at(i);
        jbyteArray jch = jenv->NewByteArray(ch.size());
        jenv->SetByteArrayRegion(jch, 0, ch.size(), (const jbyte *) ch.data());
        jenv->SetObjectArrayElement(jresult, i, jch);
    }
%}
%typemap(in) std::vector<std::vector<uint8_t>> %{
    jsize $input_size = jenv->GetArrayLength($input);
    std::vector<std::vector<uint8_t>> $1_data($input_size);
    for (jsize i = 0; i < $input_size; $i++) {
        std::vector<uint8_t>& ch = $1_data->at(i);
        jbyteArray jch = (jbyteArray) jenv->GetObjectArrayElement($input, i);
        jsize ch_len = jenv->GetArraySize(jch);
        ch.resize(ch_len);
        jenv->GetByteArrayRegion(jch, 0, len, (jbyte *) ch.data());
    }
    $1 = &$1_data;
%}
%typemap(jtype) std::vector<std::vector<uint8_t>> "byte[][]"
%typemap(jstype) std::vector<std::vector<uint8_t>> "byte[][]"
%typemap(jni) std::vector<std::vector<uint8_t>> "jobjectArray"
%typemap(javaout) std::vector<std::vector<uint8_t>> {
    return $jnicall;
}

//
// CryptoBackend
//

//
// NetworkBackend
//
%extend libcdoc::NetworkBackend {
    std::vector<std::vector<uint8_t>> getPeerTLSCertificates() {
        std::vector<std::vector<uint8_t>> certs;
        $self->getPeerTLSCertificates(certs);
        return certs;
    }
}
%ignore libcdoc::NetworkBackend::getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst);

%feature("director") libcdoc::CryptoBackend;
%feature("director") libcdoc::NetworkBackend;
%feature("director") libcdoc::Configuration;
#endif

// Swig does not like visibility/declspec attributes
#define CDOC_EXPORT
// fixme: Remove this in production
#define LIBCDOC_TESTING 1

%include "CDoc.h"
%include "Wrapper.h"
%include "Recipient.h"
%include "Configuration.h"
%include "CryptoBackend.h"
%include "NetworkBackend.h"
%include "Lock.h"
%include "CDocReader.h"
%include "CDocWriter.h"

#ifdef SWIGJAVA
#endif
