// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$8 {

    static final FunctionDescriptor X509_STORE_CTX_get0_current_issuer$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_CTX_get0_current_issuer$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_CTX_get0_current_issuer",
        constants$8.X509_STORE_CTX_get0_current_issuer$FUNC, false
    );
    static final FunctionDescriptor d2i_X509_bio$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle d2i_X509_bio$MH = RuntimeHelper.downcallHandle(
        "d2i_X509_bio",
        constants$8.d2i_X509_bio$FUNC, false
    );
    static final FunctionDescriptor X509_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_free$MH = RuntimeHelper.downcallHandle(
        "X509_free",
        constants$8.X509_free$FUNC, false
    );
    static final FunctionDescriptor d2i_X509$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_X509$MH = RuntimeHelper.downcallHandle(
        "d2i_X509",
        constants$8.d2i_X509$FUNC, false
    );
    static final FunctionDescriptor i2d_X509$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_X509$MH = RuntimeHelper.downcallHandle(
        "i2d_X509",
        constants$8.i2d_X509$FUNC, false
    );
    static final FunctionDescriptor X509_get_ext_by_NID$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle X509_get_ext_by_NID$MH = RuntimeHelper.downcallHandle(
        "X509_get_ext_by_NID",
        constants$8.X509_get_ext_by_NID$FUNC, false
    );
}


