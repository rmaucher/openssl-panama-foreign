// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$892 {

    static final FunctionDescriptor PKCS12_key_gen_utf8$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS12_key_gen_utf8$MH = RuntimeHelper.downcallHandle(
        "PKCS12_key_gen_utf8",
        constants$892.PKCS12_key_gen_utf8$FUNC, false
    );
    static final FunctionDescriptor PKCS12_PBE_keyivgen$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS12_PBE_keyivgen$MH = RuntimeHelper.downcallHandle(
        "PKCS12_PBE_keyivgen",
        constants$892.PKCS12_PBE_keyivgen$FUNC, false
    );
    static final FunctionDescriptor PKCS12_gen_mac$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS12_gen_mac$MH = RuntimeHelper.downcallHandle(
        "PKCS12_gen_mac",
        constants$892.PKCS12_gen_mac$FUNC, false
    );
    static final FunctionDescriptor PKCS12_verify_mac$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS12_verify_mac$MH = RuntimeHelper.downcallHandle(
        "PKCS12_verify_mac",
        constants$892.PKCS12_verify_mac$FUNC, false
    );
    static final FunctionDescriptor PKCS12_set_mac$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle PKCS12_set_mac$MH = RuntimeHelper.downcallHandle(
        "PKCS12_set_mac",
        constants$892.PKCS12_set_mac$FUNC, false
    );
    static final FunctionDescriptor PKCS12_setup_mac$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle PKCS12_setup_mac$MH = RuntimeHelper.downcallHandle(
        "PKCS12_setup_mac",
        constants$892.PKCS12_setup_mac$FUNC, false
    );
}


