// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$168 {

    static final FunctionDescriptor BN_BLINDING_set_current_thread$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle BN_BLINDING_set_current_thread$MH = RuntimeHelper.downcallHandle(
        "BN_BLINDING_set_current_thread",
        constants$168.BN_BLINDING_set_current_thread$FUNC, false
    );
    static final FunctionDescriptor BN_BLINDING_lock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_BLINDING_lock$MH = RuntimeHelper.downcallHandle(
        "BN_BLINDING_lock",
        constants$168.BN_BLINDING_lock$FUNC, false
    );
    static final FunctionDescriptor BN_BLINDING_unlock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_BLINDING_unlock$MH = RuntimeHelper.downcallHandle(
        "BN_BLINDING_unlock",
        constants$168.BN_BLINDING_unlock$FUNC, false
    );
    static final FunctionDescriptor BN_BLINDING_get_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle BN_BLINDING_get_flags$MH = RuntimeHelper.downcallHandle(
        "BN_BLINDING_get_flags",
        constants$168.BN_BLINDING_get_flags$FUNC, false
    );
    static final FunctionDescriptor BN_BLINDING_set_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle BN_BLINDING_set_flags$MH = RuntimeHelper.downcallHandle(
        "BN_BLINDING_set_flags",
        constants$168.BN_BLINDING_set_flags$FUNC, false
    );
    static final FunctionDescriptor BN_BLINDING_create_param$bn_mod_exp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
}


