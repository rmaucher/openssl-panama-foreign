// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$619 {

    static final FunctionDescriptor PKCS7_set_cipher$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_set_cipher$MH = RuntimeHelper.downcallHandle(
        "PKCS7_set_cipher",
        constants$619.PKCS7_set_cipher$FUNC, false
    );
    static final FunctionDescriptor PKCS7_stream$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_stream$MH = RuntimeHelper.downcallHandle(
        "PKCS7_stream",
        constants$619.PKCS7_stream$FUNC, false
    );
    static final FunctionDescriptor PKCS7_get_issuer_and_serial$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS7_get_issuer_and_serial$MH = RuntimeHelper.downcallHandle(
        "PKCS7_get_issuer_and_serial",
        constants$619.PKCS7_get_issuer_and_serial$FUNC, false
    );
    static final FunctionDescriptor PKCS7_digest_from_attributes$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_digest_from_attributes$MH = RuntimeHelper.downcallHandle(
        "PKCS7_digest_from_attributes",
        constants$619.PKCS7_digest_from_attributes$FUNC, false
    );
    static final FunctionDescriptor PKCS7_add_signed_attribute$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle PKCS7_add_signed_attribute$MH = RuntimeHelper.downcallHandle(
        "PKCS7_add_signed_attribute",
        constants$619.PKCS7_add_signed_attribute$FUNC, false
    );
    static final FunctionDescriptor PKCS7_add_attribute$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle PKCS7_add_attribute$MH = RuntimeHelper.downcallHandle(
        "PKCS7_add_attribute",
        constants$619.PKCS7_add_attribute$FUNC, false
    );
}


