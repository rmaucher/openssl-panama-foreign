// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$647 {

    static final FunctionDescriptor X509_get_pathlen$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle X509_get_pathlen$MH = RuntimeHelper.downcallHandle(
        "X509_get_pathlen",
        constants$647.X509_get_pathlen$FUNC, false
    );
    static final FunctionDescriptor i2d_PUBKEY$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_PUBKEY$MH = RuntimeHelper.downcallHandle(
        "i2d_PUBKEY",
        constants$647.i2d_PUBKEY$FUNC, false
    );
    static final FunctionDescriptor d2i_PUBKEY$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PUBKEY$MH = RuntimeHelper.downcallHandle(
        "d2i_PUBKEY",
        constants$647.d2i_PUBKEY$FUNC, false
    );
    static final FunctionDescriptor i2d_RSA_PUBKEY$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_RSA_PUBKEY$MH = RuntimeHelper.downcallHandle(
        "i2d_RSA_PUBKEY",
        constants$647.i2d_RSA_PUBKEY$FUNC, false
    );
    static final FunctionDescriptor d2i_RSA_PUBKEY$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_RSA_PUBKEY$MH = RuntimeHelper.downcallHandle(
        "d2i_RSA_PUBKEY",
        constants$647.d2i_RSA_PUBKEY$FUNC, false
    );
    static final FunctionDescriptor i2d_DSA_PUBKEY$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_DSA_PUBKEY$MH = RuntimeHelper.downcallHandle(
        "i2d_DSA_PUBKEY",
        constants$647.i2d_DSA_PUBKEY$FUNC, false
    );
}


