// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$662 {

    static final FunctionDescriptor d2i_X509_CRL$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_X509_CRL$MH = RuntimeHelper.downcallHandle(
        "d2i_X509_CRL",
        constants$662.d2i_X509_CRL$FUNC, false
    );
    static final FunctionDescriptor i2d_X509_CRL$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_X509_CRL$MH = RuntimeHelper.downcallHandle(
        "i2d_X509_CRL",
        constants$662.i2d_X509_CRL$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_add0_revoked$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_CRL_add0_revoked$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_add0_revoked",
        constants$662.X509_CRL_add0_revoked$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_get0_by_serial$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_CRL_get0_by_serial$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_get0_by_serial",
        constants$662.X509_CRL_get0_by_serial$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_get0_by_cert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_CRL_get0_by_cert$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_get0_by_cert",
        constants$662.X509_CRL_get0_by_cert$FUNC, false
    );
    static final FunctionDescriptor X509_PKEY_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_PKEY_new$MH = RuntimeHelper.downcallHandle(
        "X509_PKEY_new",
        constants$662.X509_PKEY_new$FUNC, false
    );
}


