// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$941 {

    static final FunctionDescriptor sk_GENERAL_NAME_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAME_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAME_set_cmp_func",
        constants$941.sk_GENERAL_NAME_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$941.sk_GENERAL_NAMES_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$941.sk_GENERAL_NAMES_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
}

