// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$42 {

    static final FunctionDescriptor OPENSSL_sk_pop_free$func$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_pop_free$func$MH = RuntimeHelper.downcallHandle(
        constants$42.OPENSSL_sk_pop_free$func$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_pop_free$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_pop_free",
        constants$42.OPENSSL_sk_pop_free$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_deep_copy$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_deep_copy",
        constants$42.OPENSSL_sk_deep_copy$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle OPENSSL_sk_insert$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_insert",
        constants$42.OPENSSL_sk_insert$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle OPENSSL_sk_delete$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_delete",
        constants$42.OPENSSL_sk_delete$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_delete_ptr",
        constants$42.OPENSSL_sk_delete_ptr$FUNC, false
    );
}

