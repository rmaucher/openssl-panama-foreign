// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$420 {

    static final FunctionDescriptor EC_KEY_METHOD_get_verify$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_METHOD_get_verify$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_METHOD_get_verify",
        constants$420.EC_KEY_METHOD_get_verify$FUNC, false
    );
    static final FunctionDescriptor ERR_load_RSA_strings$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_load_RSA_strings$MH = RuntimeHelper.downcallHandle(
        "ERR_load_RSA_strings",
        constants$420.ERR_load_RSA_strings$FUNC, false
    );
    static final FunctionDescriptor RSA_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle RSA_new$MH = RuntimeHelper.downcallHandle(
        "RSA_new",
        constants$420.RSA_new$FUNC, false
    );
    static final FunctionDescriptor RSA_new_method$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_new_method$MH = RuntimeHelper.downcallHandle(
        "RSA_new_method",
        constants$420.RSA_new_method$FUNC, false
    );
    static final FunctionDescriptor RSA_bits$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RSA_bits$MH = RuntimeHelper.downcallHandle(
        "RSA_bits",
        constants$420.RSA_bits$FUNC, false
    );
    static final FunctionDescriptor RSA_size$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RSA_size$MH = RuntimeHelper.downcallHandle(
        "RSA_size",
        constants$420.RSA_size$FUNC, false
    );
}

