// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1113 {

    static final FunctionDescriptor ENGINE_get_pkey_meth_engine$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ENGINE_get_pkey_meth_engine$MH = RuntimeHelper.downcallHandle(
        "ENGINE_get_pkey_meth_engine",
        constants$1113.ENGINE_get_pkey_meth_engine$FUNC, false
    );
    static final FunctionDescriptor ENGINE_get_pkey_asn1_meth_engine$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ENGINE_get_pkey_asn1_meth_engine$MH = RuntimeHelper.downcallHandle(
        "ENGINE_get_pkey_asn1_meth_engine",
        constants$1113.ENGINE_get_pkey_asn1_meth_engine$FUNC, false
    );
    static final FunctionDescriptor ENGINE_set_default_RSA$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle ENGINE_set_default_RSA$MH = RuntimeHelper.downcallHandle(
        "ENGINE_set_default_RSA",
        constants$1113.ENGINE_set_default_RSA$FUNC, false
    );
    static final FunctionDescriptor ENGINE_set_default_string$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ENGINE_set_default_string$MH = RuntimeHelper.downcallHandle(
        "ENGINE_set_default_string",
        constants$1113.ENGINE_set_default_string$FUNC, false
    );
    static final FunctionDescriptor ENGINE_set_default_DSA$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle ENGINE_set_default_DSA$MH = RuntimeHelper.downcallHandle(
        "ENGINE_set_default_DSA",
        constants$1113.ENGINE_set_default_DSA$FUNC, false
    );
    static final FunctionDescriptor ENGINE_set_default_EC$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle ENGINE_set_default_EC$MH = RuntimeHelper.downcallHandle(
        "ENGINE_set_default_EC",
        constants$1113.ENGINE_set_default_EC$FUNC, false
    );
}

