// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$151 {

    static final FunctionDescriptor BN_secure_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle BN_secure_new$MH = RuntimeHelper.downcallHandle(
        "BN_secure_new",
        constants$151.BN_secure_new$FUNC, false
    );
    static final FunctionDescriptor BN_clear_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle BN_clear_free$MH = RuntimeHelper.downcallHandle(
        "BN_clear_free",
        constants$151.BN_clear_free$FUNC, false
    );
    static final FunctionDescriptor BN_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BN_copy$MH = RuntimeHelper.downcallHandle(
        "BN_copy",
        constants$151.BN_copy$FUNC, false
    );
    static final FunctionDescriptor BN_swap$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BN_swap$MH = RuntimeHelper.downcallHandle(
        "BN_swap",
        constants$151.BN_swap$FUNC, false
    );
    static final FunctionDescriptor BN_bin2bn$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_bin2bn$MH = RuntimeHelper.downcallHandle(
        "BN_bin2bn",
        constants$151.BN_bin2bn$FUNC, false
    );
    static final FunctionDescriptor BN_bn2bin$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BN_bn2bin$MH = RuntimeHelper.downcallHandle(
        "BN_bn2bin",
        constants$151.BN_bn2bin$FUNC, false
    );
}

