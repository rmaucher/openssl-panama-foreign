// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$652 {

    static final FunctionDescriptor d2i_X509_EXTENSION$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_X509_EXTENSION$MH = RuntimeHelper.downcallHandle(
        "d2i_X509_EXTENSION",
        constants$652.d2i_X509_EXTENSION$FUNC, false
    );
    static final FunctionDescriptor i2d_X509_EXTENSION$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_X509_EXTENSION$MH = RuntimeHelper.downcallHandle(
        "i2d_X509_EXTENSION",
        constants$652.i2d_X509_EXTENSION$FUNC, false
    );
    static final FunctionDescriptor d2i_X509_EXTENSIONS$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_X509_EXTENSIONS$MH = RuntimeHelper.downcallHandle(
        "d2i_X509_EXTENSIONS",
        constants$652.d2i_X509_EXTENSIONS$FUNC, false
    );
    static final FunctionDescriptor i2d_X509_EXTENSIONS$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_X509_EXTENSIONS$MH = RuntimeHelper.downcallHandle(
        "i2d_X509_EXTENSIONS",
        constants$652.i2d_X509_EXTENSIONS$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_NAME_ENTRY_new$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_new",
        constants$652.X509_NAME_ENTRY_new$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_NAME_ENTRY_free$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_free",
        constants$652.X509_NAME_ENTRY_free$FUNC, false
    );
}


