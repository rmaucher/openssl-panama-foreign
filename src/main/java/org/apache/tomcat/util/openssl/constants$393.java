// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$393 {

    static final FunctionDescriptor EC_POINT_set_compressed_coordinates_GFp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_POINT_set_compressed_coordinates_GFp$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_set_compressed_coordinates_GFp",
        constants$393.EC_POINT_set_compressed_coordinates_GFp$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_point2oct$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle EC_POINT_point2oct$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_point2oct",
        constants$393.EC_POINT_point2oct$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_oct2point$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle EC_POINT_oct2point$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_oct2point",
        constants$393.EC_POINT_oct2point$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_point2buf$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_point2buf$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_point2buf",
        constants$393.EC_POINT_point2buf$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_point2bn$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_point2bn$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_point2bn",
        constants$393.EC_POINT_point2bn$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_bn2point$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_bn2point$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_bn2point",
        constants$393.EC_POINT_bn2point$FUNC, false
    );
}


