// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$627 {

    static final FunctionDescriptor NETSCAPE_SPKI_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle NETSCAPE_SPKI_print$MH = RuntimeHelper.downcallHandle(
        "NETSCAPE_SPKI_print",
        constants$627.NETSCAPE_SPKI_print$FUNC, false
    );
    static final FunctionDescriptor X509_signature_dump$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_signature_dump$MH = RuntimeHelper.downcallHandle(
        "X509_signature_dump",
        constants$627.X509_signature_dump$FUNC, false
    );
    static final FunctionDescriptor X509_signature_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_signature_print$MH = RuntimeHelper.downcallHandle(
        "X509_signature_print",
        constants$627.X509_signature_print$FUNC, false
    );
    static final FunctionDescriptor X509_sign$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_sign$MH = RuntimeHelper.downcallHandle(
        "X509_sign",
        constants$627.X509_sign$FUNC, false
    );
    static final FunctionDescriptor X509_sign_ctx$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_sign_ctx$MH = RuntimeHelper.downcallHandle(
        "X509_sign_ctx",
        constants$627.X509_sign_ctx$FUNC, false
    );
    static final FunctionDescriptor X509_http_nbio$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_http_nbio$MH = RuntimeHelper.downcallHandle(
        "X509_http_nbio",
        constants$627.X509_http_nbio$FUNC, false
    );
}

