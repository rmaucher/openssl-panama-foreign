// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$613 {

    static final FunctionDescriptor d2i_PKCS7_DIGEST$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS7_DIGEST$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS7_DIGEST",
        constants$613.d2i_PKCS7_DIGEST$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7_DIGEST$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7_DIGEST$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7_DIGEST",
        constants$613.i2d_PKCS7_DIGEST$FUNC, false
    );
    static final FunctionDescriptor PKCS7_ENCRYPT_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle PKCS7_ENCRYPT_new$MH = RuntimeHelper.downcallHandle(
        "PKCS7_ENCRYPT_new",
        constants$613.PKCS7_ENCRYPT_new$FUNC, false
    );
    static final FunctionDescriptor PKCS7_ENCRYPT_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle PKCS7_ENCRYPT_free$MH = RuntimeHelper.downcallHandle(
        "PKCS7_ENCRYPT_free",
        constants$613.PKCS7_ENCRYPT_free$FUNC, false
    );
    static final FunctionDescriptor d2i_PKCS7_ENCRYPT$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS7_ENCRYPT$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS7_ENCRYPT",
        constants$613.d2i_PKCS7_ENCRYPT$FUNC, false
    );
    static final FunctionDescriptor i2d_PKCS7_ENCRYPT$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PKCS7_ENCRYPT$MH = RuntimeHelper.downcallHandle(
        "i2d_PKCS7_ENCRYPT",
        constants$613.i2d_PKCS7_ENCRYPT$FUNC, false
    );
}


