// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$873 {

    static final FunctionDescriptor lh_ERR_STRING_DATA_set_down_load$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle lh_ERR_STRING_DATA_set_down_load$MH = RuntimeHelper.downcallHandle(
        "lh_ERR_STRING_DATA_set_down_load",
        constants$873.lh_ERR_STRING_DATA_set_down_load$FUNC, false
    );
    static final FunctionDescriptor lh_ERR_STRING_DATA_doall$doall$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle lh_ERR_STRING_DATA_doall$doall$MH = RuntimeHelper.downcallHandle(
        constants$873.lh_ERR_STRING_DATA_doall$doall$FUNC, false
    );
    static final FunctionDescriptor lh_ERR_STRING_DATA_doall$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle lh_ERR_STRING_DATA_doall$MH = RuntimeHelper.downcallHandle(
        "lh_ERR_STRING_DATA_doall",
        constants$873.lh_ERR_STRING_DATA_doall$FUNC, false
    );
    static final FunctionDescriptor ERR_put_error$FUNC = FunctionDescriptor.ofVoid(
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ERR_put_error$MH = RuntimeHelper.downcallHandle(
        "ERR_put_error",
        constants$873.ERR_put_error$FUNC, false
    );
    static final FunctionDescriptor ERR_set_error_data$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ERR_set_error_data$MH = RuntimeHelper.downcallHandle(
        "ERR_set_error_data",
        constants$873.ERR_set_error_data$FUNC, false
    );
}


