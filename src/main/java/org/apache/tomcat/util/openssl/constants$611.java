// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$611 {

    static final FunctionDescriptor d2i_PKCS7_ENC_CONTENT$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS7_ENC_CONTENT$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS7_ENC_CONTENT",
        constants$611.d2i_PKCS7_ENC_CONTENT$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7_ENC_CONTENT$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7_ENC_CONTENT$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7_ENC_CONTENT",
        constants$611.i2d_PKCS7_ENC_CONTENT$FUNC, false
    );
    static final FunctionDescriptor PKCS7_ENVELOPE_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle PKCS7_ENVELOPE_new$MH = RuntimeHelper.downcallHandle(
        "PKCS7_ENVELOPE_new",
        constants$611.PKCS7_ENVELOPE_new$FUNC, false
    );
    static final FunctionDescriptor PKCS7_ENVELOPE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle PKCS7_ENVELOPE_free$MH = RuntimeHelper.downcallHandle(
        "PKCS7_ENVELOPE_free",
        constants$611.PKCS7_ENVELOPE_free$FUNC, false
    );
    static final FunctionDescriptor d2i_PKCS7_ENVELOPE$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS7_ENVELOPE$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS7_ENVELOPE",
        constants$611.d2i_PKCS7_ENVELOPE$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7_ENVELOPE$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7_ENVELOPE$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7_ENVELOPE",
        constants$611.i2d_PKCS7_ENVELOPE$FUNC, false
    );
}


