// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$402 {

    static final FunctionDescriptor EC_KEY_generate_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_KEY_generate_key$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_generate_key",
        constants$402.EC_KEY_generate_key$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_check_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_KEY_check_key$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_check_key",
        constants$402.EC_KEY_check_key$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_can_sign$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_KEY_can_sign$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_can_sign",
        constants$402.EC_KEY_can_sign$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_set_public_key_affine_coordinates$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_set_public_key_affine_coordinates$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_set_public_key_affine_coordinates",
        constants$402.EC_KEY_set_public_key_affine_coordinates$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_key2buf$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_key2buf$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_key2buf",
        constants$402.EC_KEY_key2buf$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_oct2key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle EC_KEY_oct2key$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_oct2key",
        constants$402.EC_KEY_oct2key$FUNC, false
    );
}


