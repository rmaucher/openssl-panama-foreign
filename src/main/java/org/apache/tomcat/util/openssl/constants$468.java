// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$468 {

    static final FunctionDescriptor DSA_set0_pqg$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_set0_pqg$MH = RuntimeHelper.downcallHandle(
        "DSA_set0_pqg",
        constants$468.DSA_set0_pqg$FUNC, false
    );
    static final FunctionDescriptor DSA_get0_key$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_get0_key$MH = RuntimeHelper.downcallHandle(
        "DSA_get0_key",
        constants$468.DSA_get0_key$FUNC, false
    );
    static final FunctionDescriptor DSA_set0_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_set0_key$MH = RuntimeHelper.downcallHandle(
        "DSA_set0_key",
        constants$468.DSA_set0_key$FUNC, false
    );
    static final FunctionDescriptor DSA_get0_p$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_get0_p$MH = RuntimeHelper.downcallHandle(
        "DSA_get0_p",
        constants$468.DSA_get0_p$FUNC, false
    );
    static final FunctionDescriptor DSA_get0_q$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_get0_q$MH = RuntimeHelper.downcallHandle(
        "DSA_get0_q",
        constants$468.DSA_get0_q$FUNC, false
    );
    static final FunctionDescriptor DSA_get0_g$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_get0_g$MH = RuntimeHelper.downcallHandle(
        "DSA_get0_g",
        constants$468.DSA_get0_g$FUNC, false
    );
}

