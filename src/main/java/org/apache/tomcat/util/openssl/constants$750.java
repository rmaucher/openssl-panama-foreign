// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$750 {

    static final FunctionDescriptor SCT_set0_extensions$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SCT_set0_extensions$MH = RuntimeHelper.downcallHandle(
        "SCT_set0_extensions",
        constants$750.SCT_set0_extensions$FUNC, false
    );
    static final FunctionDescriptor SCT_set1_extensions$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SCT_set1_extensions$MH = RuntimeHelper.downcallHandle(
        "SCT_set1_extensions",
        constants$750.SCT_set1_extensions$FUNC, false
    );
    static final FunctionDescriptor SCT_get0_signature$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SCT_get0_signature$MH = RuntimeHelper.downcallHandle(
        "SCT_get0_signature",
        constants$750.SCT_get0_signature$FUNC, false
    );
    static final FunctionDescriptor SCT_set0_signature$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SCT_set0_signature$MH = RuntimeHelper.downcallHandle(
        "SCT_set0_signature",
        constants$750.SCT_set0_signature$FUNC, false
    );
    static final FunctionDescriptor SCT_set1_signature$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SCT_set1_signature$MH = RuntimeHelper.downcallHandle(
        "SCT_set1_signature",
        constants$750.SCT_set1_signature$FUNC, false
    );
    static final FunctionDescriptor SCT_get_source$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SCT_get_source$MH = RuntimeHelper.downcallHandle(
        "SCT_get_source",
        constants$750.SCT_get_source$FUNC, false
    );
}

