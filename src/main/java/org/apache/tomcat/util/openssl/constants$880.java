// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$880 {

    static final FunctionDescriptor sk_PKCS12_SAFEBAG_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$880.sk_PKCS12_SAFEBAG_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$880.sk_PKCS12_SAFEBAG_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_num$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_num",
        constants$880.sk_PKCS12_SAFEBAG_num$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_value$MH = RuntimeHelper.downcallHandle(
        "sk_PKCS12_SAFEBAG_value",
        constants$880.sk_PKCS12_SAFEBAG_value$FUNC, false
    );
}


