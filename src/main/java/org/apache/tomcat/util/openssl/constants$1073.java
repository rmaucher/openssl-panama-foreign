// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1073 {

    static final FunctionDescriptor ERR_load_UI_strings$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_load_UI_strings$MH = RuntimeHelper.downcallHandle(
        "ERR_load_UI_strings",
        constants$1073.ERR_load_UI_strings$FUNC, false
    );
    static final FunctionDescriptor UI_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle UI_new$MH = RuntimeHelper.downcallHandle(
        "UI_new",
        constants$1073.UI_new$FUNC, false
    );
    static final FunctionDescriptor UI_new_method$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle UI_new_method$MH = RuntimeHelper.downcallHandle(
        "UI_new_method",
        constants$1073.UI_new_method$FUNC, false
    );
    static final FunctionDescriptor UI_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle UI_free$MH = RuntimeHelper.downcallHandle(
        "UI_free",
        constants$1073.UI_free$FUNC, false
    );
    static final FunctionDescriptor UI_add_input_string$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle UI_add_input_string$MH = RuntimeHelper.downcallHandle(
        "UI_add_input_string",
        constants$1073.UI_add_input_string$FUNC, false
    );
    static final FunctionDescriptor UI_dup_input_string$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle UI_dup_input_string$MH = RuntimeHelper.downcallHandle(
        "UI_dup_input_string",
        constants$1073.UI_dup_input_string$FUNC, false
    );
}


