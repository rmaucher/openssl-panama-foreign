// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$405 {

    static final FunctionDescriptor EC_KEY_print_fp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EC_KEY_print_fp$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_print_fp",
        constants$405.EC_KEY_print_fp$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_OpenSSL$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EC_KEY_OpenSSL$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_OpenSSL",
        constants$405.EC_KEY_OpenSSL$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_get_default_method$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EC_KEY_get_default_method$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_get_default_method",
        constants$405.EC_KEY_get_default_method$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_set_default_method$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle EC_KEY_set_default_method$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_set_default_method",
        constants$405.EC_KEY_set_default_method$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_get_method$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_get_method$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_get_method",
        constants$405.EC_KEY_get_method$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_set_method$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_set_method$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_set_method",
        constants$405.EC_KEY_set_method$FUNC, false
    );
}


