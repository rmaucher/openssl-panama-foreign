// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$661 {

    static final FunctionDescriptor X509_CRL_INFO_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_CRL_INFO_new$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_INFO_new",
        constants$661.X509_CRL_INFO_new$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_INFO_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_CRL_INFO_free$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_INFO_free",
        constants$661.X509_CRL_INFO_free$FUNC, false
    );
    static final FunctionDescriptor d2i_X509_CRL_INFO$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_X509_CRL_INFO$MH = RuntimeHelper.downcallHandle(
        "d2i_X509_CRL_INFO",
        constants$661.d2i_X509_CRL_INFO$FUNC, false
    );
    static final FunctionDescriptor i2d_X509_CRL_INFO$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_X509_CRL_INFO$MH = RuntimeHelper.downcallHandle(
        "i2d_X509_CRL_INFO",
        constants$661.i2d_X509_CRL_INFO$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_CRL_new$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_new",
        constants$661.X509_CRL_new$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_CRL_free$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_free",
        constants$661.X509_CRL_free$FUNC, false
    );
}


