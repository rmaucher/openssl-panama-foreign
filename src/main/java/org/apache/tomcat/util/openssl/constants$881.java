// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$881 {

    static final FunctionDescriptor sk_PKCS12_SAFEBAG_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_new$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_new",
        constants$881.sk_PKCS12_SAFEBAG_new$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_PKCS12_SAFEBAG_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_new_null",
        constants$881.sk_PKCS12_SAFEBAG_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_new_reserve",
        constants$881.sk_PKCS12_SAFEBAG_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_reserve",
        constants$881.sk_PKCS12_SAFEBAG_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_free$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_free",
        constants$881.sk_PKCS12_SAFEBAG_free$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_zero$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_zero",
        constants$881.sk_PKCS12_SAFEBAG_zero$FUNC, false
    );
}

