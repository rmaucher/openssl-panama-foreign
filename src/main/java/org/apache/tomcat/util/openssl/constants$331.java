// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$331 {

    static final FunctionDescriptor EVP_PBE_alg_add_type$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PBE_alg_add_type$MH = RuntimeHelper.downcallHandle(
        "EVP_PBE_alg_add_type",
        constants$331.EVP_PBE_alg_add_type$FUNC, false
    );
    static final FunctionDescriptor EVP_PBE_alg_add$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PBE_alg_add$MH = RuntimeHelper.downcallHandle(
        "EVP_PBE_alg_add",
        constants$331.EVP_PBE_alg_add$FUNC, false
    );
    static final FunctionDescriptor EVP_PBE_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PBE_find$MH = RuntimeHelper.downcallHandle(
        "EVP_PBE_find",
        constants$331.EVP_PBE_find$FUNC, false
    );
    static final FunctionDescriptor EVP_PBE_cleanup$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle EVP_PBE_cleanup$MH = RuntimeHelper.downcallHandle(
        "EVP_PBE_cleanup",
        constants$331.EVP_PBE_cleanup$FUNC, false
    );
    static final FunctionDescriptor EVP_PBE_get$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EVP_PBE_get$MH = RuntimeHelper.downcallHandle(
        "EVP_PBE_get",
        constants$331.EVP_PBE_get$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_get_count$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle EVP_PKEY_asn1_get_count$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_asn1_get_count",
        constants$331.EVP_PKEY_asn1_get_count$FUNC, false
    );
}

