// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$954 {

    static final FunctionDescriptor sk_DIST_POINT_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_DIST_POINT_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_DIST_POINT_unshift",
        constants$954.sk_DIST_POINT_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_DIST_POINT_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_DIST_POINT_pop$MH = RuntimeHelper.downcallHandle(
        "sk_DIST_POINT_pop",
        constants$954.sk_DIST_POINT_pop$FUNC, false
    );
    static final FunctionDescriptor sk_DIST_POINT_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_DIST_POINT_shift$MH = RuntimeHelper.downcallHandle(
        "sk_DIST_POINT_shift",
        constants$954.sk_DIST_POINT_shift$FUNC, false
    );
    static final FunctionDescriptor sk_DIST_POINT_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_DIST_POINT_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_DIST_POINT_pop_free",
        constants$954.sk_DIST_POINT_pop_free$FUNC, false
    );
    static final FunctionDescriptor sk_DIST_POINT_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_DIST_POINT_insert$MH = RuntimeHelper.downcallHandle(
        "sk_DIST_POINT_insert",
        constants$954.sk_DIST_POINT_insert$FUNC, false
    );
    static final FunctionDescriptor sk_DIST_POINT_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_DIST_POINT_set$MH = RuntimeHelper.downcallHandle(
        "sk_DIST_POINT_set",
        constants$954.sk_DIST_POINT_set$FUNC, false
    );
}


