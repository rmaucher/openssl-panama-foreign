// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$156 {

    static final FunctionDescriptor BN_mod_lshift_quick$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_mod_lshift_quick$MH = RuntimeHelper.downcallHandle(
        "BN_mod_lshift_quick",
        constants$156.BN_mod_lshift_quick$FUNC, false
    );
    static final FunctionDescriptor BN_mod_word$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle BN_mod_word$MH = RuntimeHelper.downcallHandle(
        "BN_mod_word",
        constants$156.BN_mod_word$FUNC, false
    );
    static final FunctionDescriptor BN_div_word$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle BN_div_word$MH = RuntimeHelper.downcallHandle(
        "BN_div_word",
        constants$156.BN_div_word$FUNC, false
    );
    static final FunctionDescriptor BN_mul_word$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle BN_mul_word$MH = RuntimeHelper.downcallHandle(
        "BN_mul_word",
        constants$156.BN_mul_word$FUNC, false
    );
    static final FunctionDescriptor BN_add_word$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle BN_add_word$MH = RuntimeHelper.downcallHandle(
        "BN_add_word",
        constants$156.BN_add_word$FUNC, false
    );
    static final FunctionDescriptor BN_sub_word$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle BN_sub_word$MH = RuntimeHelper.downcallHandle(
        "BN_sub_word",
        constants$156.BN_sub_word$FUNC, false
    );
}


