// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1043 {

    static final FunctionDescriptor sk_IPAddressFamily_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressFamily_unshift",
        constants$1043.sk_IPAddressFamily_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_pop$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressFamily_pop",
        constants$1043.sk_IPAddressFamily_pop$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_shift$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressFamily_shift",
        constants$1043.sk_IPAddressFamily_shift$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressFamily_pop_free",
        constants$1043.sk_IPAddressFamily_pop_free$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_IPAddressFamily_insert$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressFamily_insert",
        constants$1043.sk_IPAddressFamily_insert$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_set$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressFamily_set",
        constants$1043.sk_IPAddressFamily_set$FUNC, false
    );
}


