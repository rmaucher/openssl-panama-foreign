// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$447 {

    static final FunctionDescriptor DH_new_method$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DH_new_method$MH = RuntimeHelper.downcallHandle(
        "DH_new_method",
        constants$447.DH_new_method$FUNC, false
    );
    static final FunctionDescriptor DH_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle DH_new$MH = RuntimeHelper.downcallHandle(
        "DH_new",
        constants$447.DH_new$FUNC, false
    );
    static final FunctionDescriptor DH_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle DH_free$MH = RuntimeHelper.downcallHandle(
        "DH_free",
        constants$447.DH_free$FUNC, false
    );
    static final FunctionDescriptor DH_up_ref$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle DH_up_ref$MH = RuntimeHelper.downcallHandle(
        "DH_up_ref",
        constants$447.DH_up_ref$FUNC, false
    );
    static final FunctionDescriptor DH_bits$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle DH_bits$MH = RuntimeHelper.downcallHandle(
        "DH_bits",
        constants$447.DH_bits$FUNC, false
    );
    static final FunctionDescriptor DH_size$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle DH_size$MH = RuntimeHelper.downcallHandle(
        "DH_size",
        constants$447.DH_size$FUNC, false
    );
}

