// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$109 {

    static final FunctionDescriptor sk_BIO_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_BIO_value$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_value",
        constants$109.sk_BIO_value$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_BIO_new$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_new",
        constants$109.sk_BIO_new$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_BIO_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_new_null",
        constants$109.sk_BIO_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_BIO_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_new_reserve",
        constants$109.sk_BIO_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_BIO_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_reserve",
        constants$109.sk_BIO_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_BIO_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_BIO_free$MH = RuntimeHelper.downcallHandle(
        "sk_BIO_free",
        constants$109.sk_BIO_free$FUNC, false
    );
}

