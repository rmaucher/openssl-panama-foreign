// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$818 {

    static final FunctionDescriptor SSL_CTX_use_PrivateKey$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_use_PrivateKey$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_use_PrivateKey",
        constants$818.SSL_CTX_use_PrivateKey$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_use_PrivateKey_ASN1$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SSL_CTX_use_PrivateKey_ASN1$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_use_PrivateKey_ASN1",
        constants$818.SSL_CTX_use_PrivateKey_ASN1$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_use_certificate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_use_certificate$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_use_certificate",
        constants$818.SSL_CTX_use_certificate$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_use_certificate_ASN1$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_use_certificate_ASN1$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_use_certificate_ASN1",
        constants$818.SSL_CTX_use_certificate_ASN1$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_use_cert_and_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_CTX_use_cert_and_key$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_use_cert_and_key",
        constants$818.SSL_CTX_use_cert_and_key$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_default_passwd_cb$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_default_passwd_cb$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_default_passwd_cb",
        constants$818.SSL_CTX_set_default_passwd_cb$FUNC, false
    );
}

