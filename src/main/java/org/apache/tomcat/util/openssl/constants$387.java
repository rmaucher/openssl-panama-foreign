// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$387 {

    static final FunctionDescriptor EC_GROUP_set_point_conversion_form$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EC_GROUP_set_point_conversion_form$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_set_point_conversion_form",
        constants$387.EC_GROUP_set_point_conversion_form$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_get_point_conversion_form$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get_point_conversion_form$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get_point_conversion_form",
        constants$387.EC_GROUP_get_point_conversion_form$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_get0_seed$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get0_seed$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get0_seed",
        constants$387.EC_GROUP_get0_seed$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_get_seed_len$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get_seed_len$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get_seed_len",
        constants$387.EC_GROUP_get_seed_len$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_set_seed$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EC_GROUP_set_seed$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_set_seed",
        constants$387.EC_GROUP_set_seed$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_set_curve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_set_curve$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_set_curve",
        constants$387.EC_GROUP_set_curve$FUNC, false
    );
}


