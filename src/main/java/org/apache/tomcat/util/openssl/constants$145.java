// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$145 {

    static final FunctionDescriptor BN_get_flags$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BN_get_flags$MH = RuntimeHelper.downcallHandle(
        "BN_get_flags",
        constants$145.BN_get_flags$FUNC, false
    );
    static final FunctionDescriptor BN_with_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BN_with_flags$MH = RuntimeHelper.downcallHandle(
        "BN_with_flags",
        constants$145.BN_with_flags$FUNC, false
    );
    static final FunctionDescriptor BN_GENCB_call$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BN_GENCB_call$MH = RuntimeHelper.downcallHandle(
        "BN_GENCB_call",
        constants$145.BN_GENCB_call$FUNC, false
    );
    static final FunctionDescriptor BN_GENCB_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle BN_GENCB_new$MH = RuntimeHelper.downcallHandle(
        "BN_GENCB_new",
        constants$145.BN_GENCB_new$FUNC, false
    );
    static final FunctionDescriptor BN_GENCB_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle BN_GENCB_free$MH = RuntimeHelper.downcallHandle(
        "BN_GENCB_free",
        constants$145.BN_GENCB_free$FUNC, false
    );
    static final FunctionDescriptor BN_GENCB_set_old$callback$FUNC = FunctionDescriptor.ofVoid(
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
}


