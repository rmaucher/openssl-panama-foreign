// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$52 {

    static final FunctionDescriptor sk_OPENSSL_CSTRING_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_zero$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_zero",
        constants$52.sk_OPENSSL_CSTRING_zero$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_OPENSSL_CSTRING_delete$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_delete",
        constants$52.sk_OPENSSL_CSTRING_delete$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_delete_ptr",
        constants$52.sk_OPENSSL_CSTRING_delete_ptr$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_push$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_push",
        constants$52.sk_OPENSSL_CSTRING_push$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_unshift",
        constants$52.sk_OPENSSL_CSTRING_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_pop$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_pop",
        constants$52.sk_OPENSSL_CSTRING_pop$FUNC, false
    );
}


