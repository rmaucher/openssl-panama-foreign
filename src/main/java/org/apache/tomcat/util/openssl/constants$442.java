// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$442 {

    static final FunctionDescriptor RSA_meth_get_init$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_meth_get_init$MH = RuntimeHelper.downcallHandle(
        "RSA_meth_get_init",
        constants$442.RSA_meth_get_init$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_set_init$init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RSA_meth_set_init$init$MH = RuntimeHelper.downcallHandle(
        constants$442.RSA_meth_set_init$init$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_set_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_meth_set_init$MH = RuntimeHelper.downcallHandle(
        "RSA_meth_set_init",
        constants$442.RSA_meth_set_init$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_get_finish$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_meth_get_finish$MH = RuntimeHelper.downcallHandle(
        "RSA_meth_get_finish",
        constants$442.RSA_meth_get_finish$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_set_finish$finish$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
}


