// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$50 {

    static final FunctionDescriptor sk_OPENSSL_CSTRING_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$50.sk_OPENSSL_CSTRING_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$50.sk_OPENSSL_CSTRING_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$50.sk_OPENSSL_CSTRING_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_CSTRING_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_CSTRING_num$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_CSTRING_num",
        constants$50.sk_OPENSSL_CSTRING_num$FUNC, false
    );
}


