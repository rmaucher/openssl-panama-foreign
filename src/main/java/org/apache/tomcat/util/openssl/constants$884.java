// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$884 {

    static final FunctionDescriptor sk_PKCS12_SAFEBAG_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_is_sorted",
        constants$884.sk_PKCS12_SAFEBAG_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_dup$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_dup",
        constants$884.sk_PKCS12_SAFEBAG_dup$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_deep_copy",
        constants$884.sk_PKCS12_SAFEBAG_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_set_cmp_func",
        constants$884.sk_PKCS12_SAFEBAG_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor PKCS12_get_attr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS12_get_attr$MH = RuntimeHelper.downcallHandle(
        "PKCS12_get_attr",
        constants$884.PKCS12_get_attr$FUNC, false
    );
    static final FunctionDescriptor PKCS8_get_attr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS8_get_attr$MH = RuntimeHelper.downcallHandle(
        "PKCS8_get_attr",
        constants$884.PKCS8_get_attr$FUNC, false
    );
}


