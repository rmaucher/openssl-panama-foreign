// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$946 {

    static final FunctionDescriptor sk_GENERAL_NAMES_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_set_cmp_func",
        constants$946.sk_GENERAL_NAMES_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_ACCESS_DESCRIPTION_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ACCESS_DESCRIPTION_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$946.sk_ACCESS_DESCRIPTION_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_ACCESS_DESCRIPTION_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ACCESS_DESCRIPTION_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$946.sk_ACCESS_DESCRIPTION_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_ACCESS_DESCRIPTION_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
}

