// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$421 {

    static final FunctionDescriptor RSA_security_bits$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RSA_security_bits$MH = RuntimeHelper.downcallHandle(
        "RSA_security_bits",
        constants$421.RSA_security_bits$FUNC, false
    );
    static final FunctionDescriptor RSA_set0_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_set0_key$MH = RuntimeHelper.downcallHandle(
        "RSA_set0_key",
        constants$421.RSA_set0_key$FUNC, false
    );
    static final FunctionDescriptor RSA_set0_factors$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_set0_factors$MH = RuntimeHelper.downcallHandle(
        "RSA_set0_factors",
        constants$421.RSA_set0_factors$FUNC, false
    );
    static final FunctionDescriptor RSA_set0_crt_params$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_set0_crt_params$MH = RuntimeHelper.downcallHandle(
        "RSA_set0_crt_params",
        constants$421.RSA_set0_crt_params$FUNC, false
    );
    static final FunctionDescriptor RSA_set0_multi_prime_params$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle RSA_set0_multi_prime_params$MH = RuntimeHelper.downcallHandle(
        "RSA_set0_multi_prime_params",
        constants$421.RSA_set0_multi_prime_params$FUNC, false
    );
    static final FunctionDescriptor RSA_get0_key$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_get0_key$MH = RuntimeHelper.downcallHandle(
        "RSA_get0_key",
        constants$421.RSA_get0_key$FUNC, false
    );
}

