// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$43 {

    static final FunctionDescriptor OPENSSL_sk_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_find$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_find",
        constants$43.OPENSSL_sk_find$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_find_ex$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_find_ex",
        constants$43.OPENSSL_sk_find_ex$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_push$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_push",
        constants$43.OPENSSL_sk_push$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_unshift$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_unshift",
        constants$43.OPENSSL_sk_unshift$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_shift$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_shift",
        constants$43.OPENSSL_sk_shift$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_pop$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_pop",
        constants$43.OPENSSL_sk_pop$FUNC, false
    );
}


