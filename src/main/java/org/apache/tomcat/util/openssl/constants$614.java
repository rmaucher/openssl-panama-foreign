// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$614 {

    static final FunctionDescriptor PKCS7_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle PKCS7_new$MH = RuntimeHelper.downcallHandle(
        "PKCS7_new",
        constants$614.PKCS7_new$FUNC, false
    );
    static final FunctionDescriptor PKCS7_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle PKCS7_free$MH = RuntimeHelper.downcallHandle(
        "PKCS7_free",
        constants$614.PKCS7_free$FUNC, false
    );
    static final FunctionDescriptor d2i_PKCS7$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS7$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS7",
        constants$614.d2i_PKCS7$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7",
        constants$614.i2d_PKCS7$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7_NDEF$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7_NDEF$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7_NDEF",
        constants$614.i2d_PKCS7_NDEF$FUNC, false
    );
    static final FunctionDescriptor PKCS7_print_ctx$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle PKCS7_print_ctx$MH = RuntimeHelper.downcallHandle(
        "PKCS7_print_ctx",
        constants$614.PKCS7_print_ctx$FUNC, false
    );
}


