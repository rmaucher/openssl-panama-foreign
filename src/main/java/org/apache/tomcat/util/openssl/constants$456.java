// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$456 {

    static final FunctionDescriptor DH_meth_get_flags$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle DH_meth_get_flags$MH = RuntimeHelper.downcallHandle(
        "DH_meth_get_flags",
        constants$456.DH_meth_get_flags$FUNC, false
    );
    static final FunctionDescriptor DH_meth_set_flags$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle DH_meth_set_flags$MH = RuntimeHelper.downcallHandle(
        "DH_meth_set_flags",
        constants$456.DH_meth_set_flags$FUNC, false
    );
    static final FunctionDescriptor DH_meth_get0_app_data$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DH_meth_get0_app_data$MH = RuntimeHelper.downcallHandle(
        "DH_meth_get0_app_data",
        constants$456.DH_meth_get0_app_data$FUNC, false
    );
    static final FunctionDescriptor DH_meth_set0_app_data$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DH_meth_set0_app_data$MH = RuntimeHelper.downcallHandle(
        "DH_meth_set0_app_data",
        constants$456.DH_meth_set0_app_data$FUNC, false
    );
    static final FunctionDescriptor DH_meth_get_generate_key$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DH_meth_get_generate_key$MH = RuntimeHelper.downcallHandle(
        "DH_meth_get_generate_key",
        constants$456.DH_meth_get_generate_key$FUNC, false
    );
    static final FunctionDescriptor DH_meth_set_generate_key$generate_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
}

