// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$391 {

    static final FunctionDescriptor EC_POINT_clear_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle EC_POINT_clear_free$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_clear_free",
        constants$391.EC_POINT_clear_free$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_copy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_copy$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_copy",
        constants$391.EC_POINT_copy$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_dup$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_dup",
        constants$391.EC_POINT_dup$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_method_of$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_method_of$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_method_of",
        constants$391.EC_POINT_method_of$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_set_to_infinity$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_set_to_infinity$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_set_to_infinity",
        constants$391.EC_POINT_set_to_infinity$FUNC, false
    );
    static final FunctionDescriptor EC_POINT_set_Jprojective_coordinates_GFp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_POINT_set_Jprojective_coordinates_GFp$MH = RuntimeHelper.downcallHandle(
        "EC_POINT_set_Jprojective_coordinates_GFp",
        constants$391.EC_POINT_set_Jprojective_coordinates_GFp$FUNC, false
    );
}


