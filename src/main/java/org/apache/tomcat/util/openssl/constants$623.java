// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$623 {

    static final FunctionDescriptor SMIME_read_PKCS7$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SMIME_read_PKCS7$MH = RuntimeHelper.downcallHandle(
        "SMIME_read_PKCS7",
        constants$623.SMIME_read_PKCS7$FUNC, false
    );
    static final FunctionDescriptor BIO_new_PKCS7$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_new_PKCS7$MH = RuntimeHelper.downcallHandle(
        "BIO_new_PKCS7",
        constants$623.BIO_new_PKCS7$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_set_default_method$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_CRL_set_default_method$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_set_default_method",
        constants$623.X509_CRL_set_default_method$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_METHOD_new$crl_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_CRL_METHOD_new$crl_init$MH = RuntimeHelper.downcallHandle(
        constants$623.X509_CRL_METHOD_new$crl_init$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_METHOD_new$crl_free$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
}

