// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$748 {

    static final FunctionDescriptor SCT_get_version$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SCT_get_version$MH = RuntimeHelper.downcallHandle(
        "SCT_get_version",
        constants$748.SCT_get_version$FUNC, false
    );
    static final FunctionDescriptor SCT_set_version$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SCT_set_version$MH = RuntimeHelper.downcallHandle(
        "SCT_set_version",
        constants$748.SCT_set_version$FUNC, false
    );
    static final FunctionDescriptor SCT_get_log_entry_type$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SCT_get_log_entry_type$MH = RuntimeHelper.downcallHandle(
        "SCT_get_log_entry_type",
        constants$748.SCT_get_log_entry_type$FUNC, false
    );
    static final FunctionDescriptor SCT_set_log_entry_type$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SCT_set_log_entry_type$MH = RuntimeHelper.downcallHandle(
        "SCT_set_log_entry_type",
        constants$748.SCT_set_log_entry_type$FUNC, false
    );
    static final FunctionDescriptor SCT_get0_log_id$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SCT_get0_log_id$MH = RuntimeHelper.downcallHandle(
        "SCT_get0_log_id",
        constants$748.SCT_get0_log_id$FUNC, false
    );
    static final FunctionDescriptor SCT_set0_log_id$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SCT_set0_log_id$MH = RuntimeHelper.downcallHandle(
        "SCT_set0_log_id",
        constants$748.SCT_set0_log_id$FUNC, false
    );
}


