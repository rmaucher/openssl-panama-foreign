// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$610 {

    static final FunctionDescriptor PKCS7_SIGNED_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle PKCS7_SIGNED_new$MH = RuntimeHelper.downcallHandle(
        "PKCS7_SIGNED_new",
        constants$610.PKCS7_SIGNED_new$FUNC, false
    );
    static final FunctionDescriptor PKCS7_SIGNED_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle PKCS7_SIGNED_free$MH = RuntimeHelper.downcallHandle(
        "PKCS7_SIGNED_free",
        constants$610.PKCS7_SIGNED_free$FUNC, false
    );
    static final FunctionDescriptor d2i_PKCS7_SIGNED$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS7_SIGNED$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS7_SIGNED",
        constants$610.d2i_PKCS7_SIGNED$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7_SIGNED$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7_SIGNED$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7_SIGNED",
        constants$610.i2d_PKCS7_SIGNED$FUNC, false
    );
    static final FunctionDescriptor PKCS7_ENC_CONTENT_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle PKCS7_ENC_CONTENT_new$MH = RuntimeHelper.downcallHandle(
        "PKCS7_ENC_CONTENT_new",
        constants$610.PKCS7_ENC_CONTENT_new$FUNC, false
    );
    static final FunctionDescriptor PKCS7_ENC_CONTENT_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle PKCS7_ENC_CONTENT_free$MH = RuntimeHelper.downcallHandle(
        "PKCS7_ENC_CONTENT_free",
        constants$610.PKCS7_ENC_CONTENT_free$FUNC, false
    );
}

