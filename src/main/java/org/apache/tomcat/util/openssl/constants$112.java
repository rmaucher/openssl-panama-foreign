// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$112 {

    static final FunctionDescriptor sk_BIO_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_BIO_sort$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_sort",
        constants$112.sk_BIO_sort$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_BIO_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_is_sorted",
        constants$112.sk_BIO_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_BIO_dup$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_dup",
        constants$112.sk_BIO_dup$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_BIO_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_deep_copy",
        constants$112.sk_BIO_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_BIO_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_set_cmp_func",
        constants$112.sk_BIO_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor asn1_ps_func$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
}


