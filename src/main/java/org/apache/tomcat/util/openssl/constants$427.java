// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$427 {

    static final FunctionDescriptor RSA_public_decrypt$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle RSA_public_decrypt$MH = RuntimeHelper.downcallHandle(
        "RSA_public_decrypt",
        constants$427.RSA_public_decrypt$FUNC, false
    );
    static final FunctionDescriptor RSA_private_decrypt$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle RSA_private_decrypt$MH = RuntimeHelper.downcallHandle(
        "RSA_private_decrypt",
        constants$427.RSA_private_decrypt$FUNC, false
    );
    static final FunctionDescriptor RSA_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle RSA_free$MH = RuntimeHelper.downcallHandle(
        "RSA_free",
        constants$427.RSA_free$FUNC, false
    );
    static final FunctionDescriptor RSA_up_ref$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RSA_up_ref$MH = RuntimeHelper.downcallHandle(
        "RSA_up_ref",
        constants$427.RSA_up_ref$FUNC, false
    );
    static final FunctionDescriptor RSA_flags$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RSA_flags$MH = RuntimeHelper.downcallHandle(
        "RSA_flags",
        constants$427.RSA_flags$FUNC, false
    );
    static final FunctionDescriptor RSA_set_default_method$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle RSA_set_default_method$MH = RuntimeHelper.downcallHandle(
        "RSA_set_default_method",
        constants$427.RSA_set_default_method$FUNC, false
    );
}


