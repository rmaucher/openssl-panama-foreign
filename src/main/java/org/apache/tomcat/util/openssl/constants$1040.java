// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1040 {

    static final FunctionDescriptor sk_IPAddressOrRange_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_set_cmp_func",
        constants$1040.sk_IPAddressOrRange_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$1040.sk_IPAddressFamily_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_IPAddressFamily_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$1040.sk_IPAddressFamily_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressFamily_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
}


