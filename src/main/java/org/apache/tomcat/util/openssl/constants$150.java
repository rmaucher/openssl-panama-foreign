// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$150 {

    static final FunctionDescriptor BN_pseudo_rand$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BN_pseudo_rand$MH = RuntimeHelper.downcallHandle(
        "BN_pseudo_rand",
        constants$150.BN_pseudo_rand$FUNC, false
    );
    static final FunctionDescriptor BN_pseudo_rand_range$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BN_pseudo_rand_range$MH = RuntimeHelper.downcallHandle(
        "BN_pseudo_rand_range",
        constants$150.BN_pseudo_rand_range$FUNC, false
    );
    static final FunctionDescriptor BN_num_bits$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_num_bits$MH = RuntimeHelper.downcallHandle(
        "BN_num_bits",
        constants$150.BN_num_bits$FUNC, false
    );
    static final FunctionDescriptor BN_num_bits_word$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG
    );
    static final MethodHandle BN_num_bits_word$MH = RuntimeHelper.downcallHandle(
        "BN_num_bits_word",
        constants$150.BN_num_bits_word$FUNC, false
    );
    static final FunctionDescriptor BN_security_bits$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BN_security_bits$MH = RuntimeHelper.downcallHandle(
        "BN_security_bits",
        constants$150.BN_security_bits$FUNC, false
    );
    static final FunctionDescriptor BN_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle BN_new$MH = RuntimeHelper.downcallHandle(
        "BN_new",
        constants$150.BN_new$FUNC, false
    );
}

