// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$620 {

    static final FunctionDescriptor PKCS7_get_attribute$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS7_get_attribute$MH = RuntimeHelper.downcallHandle(
        "PKCS7_get_attribute",
        constants$620.PKCS7_get_attribute$FUNC, false
    );
    static final FunctionDescriptor PKCS7_get_signed_attribute$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS7_get_signed_attribute$MH = RuntimeHelper.downcallHandle(
        "PKCS7_get_signed_attribute",
        constants$620.PKCS7_get_signed_attribute$FUNC, false
    );
    static final FunctionDescriptor PKCS7_set_signed_attributes$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_set_signed_attributes$MH = RuntimeHelper.downcallHandle(
        "PKCS7_set_signed_attributes",
        constants$620.PKCS7_set_signed_attributes$FUNC, false
    );
    static final FunctionDescriptor PKCS7_set_attributes$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_set_attributes$MH = RuntimeHelper.downcallHandle(
        "PKCS7_set_attributes",
        constants$620.PKCS7_set_attributes$FUNC, false
    );
    static final FunctionDescriptor PKCS7_sign$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS7_sign$MH = RuntimeHelper.downcallHandle(
        "PKCS7_sign",
        constants$620.PKCS7_sign$FUNC, false
    );
    static final FunctionDescriptor PKCS7_sign_add_signer$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS7_sign_add_signer$MH = RuntimeHelper.downcallHandle(
        "PKCS7_sign_add_signer",
        constants$620.PKCS7_sign_add_signer$FUNC, false
    );
}


