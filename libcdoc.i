%module(directors="1") CDoc

%{
#include "libcdoc/CDoc.h"
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
%apply long long { result_t }
%apply long long { int64_t }
%apply long long { uint64_t }
%apply int { int32_t }

%typemap(javaout) libcdoc::result_t %{
{
    // javaout(result_t)
    long result = $jnicall;
    if (result == CDoc.IO_ERROR) throw new IOException(this.getLastErrorStr());
    return result;
}
%}

%javaexception("ee.ria.libcdoc.CDocException") libcdoc::CDocReader::beginDecryption {
    $action;
    if (result < 0) {
        std::string err_str = arg1->getLastErrorStr();
        jclass clazz = jenv->FindClass("ee/ria/libcdoc/CDocException");
        jenv->ThrowNew(clazz, err_str.c_str());
        return $null;
    }
}

//
// const uint8_t *src <- byte[]
//

%typemap(in) (const uint8_t *src) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
%}
%typemap(javain) const uint8_t *src "$javainput"
%typemap(jni) const uint8_t *src "jbyteArray"
%typemap(jtype) const uint8_t *src "byte[]"
%typemap(jstype) const uint8_t *src "byte[]"

//
// const uint8_t *src, size_t len <- byte[]
//

    %typemap(in) (const uint8_t *src, size_t size) %{
    $1 = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    $2 = jenv->GetArrayLength($input);
%}
%typemap(javain) (const uint8_t *src, size_t size) "$javainput"
%typemap(jni) (const uint8_t *src, size_t size) "jbyteArray"
%typemap(jtype) (const uint8_t *src, size_t size) "byte[]"
%typemap(jstype) (const uint8_t *src, size_t size) "byte[]"

//
// uint8_t *dst, size_t size <- byte[]
//

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

//
// std::vector<uint8_t>& -> byte[]
//

%typemap(in) (std::vector<uint8_t>&) %{
    // std::vector<uint8_t>& in
    jsize $input_size = jenv->GetArrayLength($input);
    uint8_t *$input_data = (uint8_t *) jenv->GetByteArrayElements($input, NULL);
    std::vector<uint8_t> $1_vec($input_data, $input_data + $input_size);
    jenv->ReleaseByteArrayElements($input, (jbyte *) $input_data, 0);
    $1 = &$1_vec;

%}
%typemap(freearg) (std::vector<uint8_t>&) %{
    // std::vector<uint8_t>& freearg
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
    // DataBuffer out
%}
%typemap(freearg) std::vector<uint8_t>& dst %{
    // DataBuffer freearg
%}
%typemap(in) std::vector<uint8_t>& dst %{
    // DataBuffer in
    jclass $1_class = jenv->FindClass("ee/ria/libcdoc/DataBuffer");
    jmethodID $1_mid = jenv->GetStaticMethodID($1_class, "getCPtr", "(Lee/ria/libcdoc/DataBuffer;)J");
    jlong $1_cptr = jenv->CallStaticLongMethod($1_class, $1_mid, $input);
    libcdoc::DataBuffer *$1_db = (libcdoc::DataBuffer *) $1_cptr;
    $1 = $1_db->data;
%}
%typemap(jtype) std::vector<uint8_t>& dst "DataBuffer"
%typemap(jstype) std::vector<uint8_t>& dst "DataBuffer"
%typemap(jni) std::vector<uint8_t>& dst "jobject"
%typemap(javaout) std::vector<uint8_t>& dst "$jnicall"
%typemap(javain) std::vector<uint8_t>& dst "$javainput"
%typemap(directorin,descriptor="Lee/ria/libcdoc/DataBuffer;") std::vector<uint8_t>& dst %{
    // DataBuffer directorin

    // Use scope guard to reset DataBuffer after Java call
    auto del = [&] (libcdoc::DataBuffer *db) {
        // std::cerr << "deleting DataBuffer\n";
        db->reset();
    };
    std::unique_ptr<libcdoc::DataBuffer, decltype(del)> $1_db(new libcdoc::DataBuffer(&$1), del);

    jclass buf_class = jenv->FindClass("ee/ria/libcdoc/DataBuffer");
    jmethodID mid = jenv->GetMethodID(buf_class, "<init>", "(JZ)V");
    jobject obj = jenv->NewObject(buf_class, mid, (jlong) $1_db.get(), JNI_FALSE);
    $input = obj;
%}
%typemap(directorout) std::vector<uint8_t>& dst %{
    // DataBuffer directorout
%}
%typemap(javadirectorin) std::vector<uint8_t>& dst "$jniinput"
%typemap(javadirectorout) std::vector<uint8_t>& dst %{
    // DataBuffer javadirectorout
    $javacall
%}

//
// std::vector<std::vector<uint8_t>> <- CertificateList
//

%typemap(out) std::vector<std::vector<uint8_t>>& %{
    // CertificateList out
%}
%typemap(in) std::vector<std::vector<uint8_t>>& %{
    // CertificateList in
    std::cerr << "%typemap(in) std::vector<std::vector<uint8_t>>&" << std::endl;
    jclass $1_class = jenv->FindClass("ee/ria/libcdoc/CertificateList");
    jmethodID $1_mid = jenv->GetStaticMethodID($1_class, "getCPtr", "(Lee/ria/libcdoc/CertificateList;)J");
    jlong $1_cptr = jenv->CallStaticLongMethod($1_class, $1_mid, $input);
    libcdoc::CertificateList *$1_db = (libcdoc::CertificateList *) $1_cptr;
    $1 = $1_db->data;
%}
%typemap(freearg) std::vector<std::vector<uint8_t>>& %{
    // std::vector<std::vector<uint8_t>>& freearg
%}
%typemap(jtype) std::vector<std::vector<uint8_t>>& "CertificateList"
%typemap(jstype) std::vector<std::vector<uint8_t>>& "CertificateList"
%typemap(jni) std::vector<std::vector<uint8_t>>& "jobject"
%typemap(javaout) std::vector<std::vector<uint8_t>>& %{
    // std::vector<std::vector<uint8_t>>& javaout
    return $jnicall;
%}
%typemap(javain) std::vector<std::vector<uint8_t>>& "$javainput"

%typemap(directorin,descriptor="Lee/ria/libcdoc/CertificateList;") std::vector<std::vector<uint8_t>>& %{
    // CertificateList directorin

    // Use scope guard to reset CertificateList after Java call
    auto del = [&] (libcdoc::CertificateList *db) {
        // std::cerr << "deleting CertificateList\n";
        db->reset();
    };
    std::unique_ptr<libcdoc::CertificateList, decltype(del)> $1_db(new libcdoc::CertificateList(&$1), del);

    jclass buf_class = jenv->FindClass("ee/ria/libcdoc/CertificateList");
    jmethodID mid = jenv->GetMethodID(buf_class, "<init>", "(JZ)V");
    jobject obj = jenv->NewObject(buf_class, mid, (jlong) $1_db.get(), JNI_FALSE);
    $input = obj;
%}
%typemap(directorout) std::vector<std::vector<uint8_t>>& %{
    std::cerr << "%typemap(directorout) std::vector<std::vector<uint8_t>>&" << std::endl;
    // std::vector<std::vector<uint8_t>>& directorout
%}
%typemap(javadirectorin) std::vector<std::vector<uint8_t>>& "$jniinput"
%typemap(javadirectorout) std::vector<std::vector<uint8_t>>& %{
    // std::vector<std::vector<uint8_t>>& javadirectorout
    $javacall
%}

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

%extend libcdoc::CDocWriter {
    int64_t writeData(const uint8_t *src, size_t pos, size_t size) {
        return $self->writeData(src + pos, size);
    }
};

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
    import java.util.ArrayList;
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

//
// DataBuffer
//

%ignore libcdoc::DataBuffer::data;
%ignore libcdoc::DataBuffer::DataBuffer(std::vector<uint8_t> *_data);
%ignore libcdoc::DataBuffer::reset();

//
// CertificateList
//

%ignore libcdoc::CertificateList::data;
%ignore libcdoc::CertificateList::CertificateList(std::vector<std::vector<uint8_t>> *_data);
%ignore libcdoc::CertificateList::reset();

//
// Recipient
//

%ignore libcdoc::Recipient::rcpt_key;
%ignore libcdoc::Recipient::cert;
%ignore libcdoc::Recipient::buildLabel(std::vector<std::pair<std::string_view, std::string_view>> components);
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
    static std::string buildLabel(const std::vector<std::string>& values) {
        std::vector<std::pair<std::string_view, std::string_view>> vec;
        for (size_t i = 0; (i + 1) < values.size(); i += 2) {
            vec.push_back({values[i], values[i + 1]});
        }
        return libcdoc::Recipient::buildLabel(vec);
    }
};

//
// Lock
//

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

//
// CryptoBackend
//

//
// NetworkBackend
//

%typemap(javaimports) ArrayList<byte[]> %{
    import java.util.ArrayList;
%}

%typemap(javaimports) std::vector<std::vector<uint8_t>>& %{
    import java.util.ArrayList;
%}
%typemap(javaimports) libcdoc::NetworkBackend %{
import java.util.ArrayList;
    %}

//%extend libcdoc::NetworkBackend {
//    std::vector<std::vector<uint8_t>> getPeerTLSCertificates() {
//        std::vector<std::vector<uint8_t>> certs;
//        $self->getPeerTLSCertificates(certs);
//        return certs;
//    }
//}
//%ignore libcdoc::NetworkBackend::getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst);

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
