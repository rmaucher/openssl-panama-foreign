// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$751 {

    static final FunctionDescriptor SCT_set_source$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SCT_set_source$MH = RuntimeHelper.downcallHandle(
        "SCT_set_source",
        constants$751.SCT_set_source$FUNC, false
    );
    static final FunctionDescriptor SCT_validation_status_string$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SCT_validation_status_string$MH = RuntimeHelper.downcallHandle(
        "SCT_validation_status_string",
        constants$751.SCT_validation_status_string$FUNC, false
    );
    static final FunctionDescriptor SCT_print$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SCT_print$MH = RuntimeHelper.downcallHandle(
        "SCT_print",
        constants$751.SCT_print$FUNC, false
    );
    static final FunctionDescriptor SCT_LIST_print$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SCT_LIST_print$MH = RuntimeHelper.downcallHandle(
        "SCT_LIST_print",
        constants$751.SCT_LIST_print$FUNC, false
    );
    static final FunctionDescriptor SCT_get_validation_status$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SCT_get_validation_status$MH = RuntimeHelper.downcallHandle(
        "SCT_get_validation_status",
        constants$751.SCT_get_validation_status$FUNC, false
    );
    static final FunctionDescriptor SCT_validate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SCT_validate$MH = RuntimeHelper.downcallHandle(
        "SCT_validate",
        constants$751.SCT_validate$FUNC, false
    );
}

