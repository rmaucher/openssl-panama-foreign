// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$651 {

    static final FunctionDescriptor X509_ATTRIBUTE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_ATTRIBUTE_free$MH = RuntimeHelper.downcallHandle(
        "X509_ATTRIBUTE_free",
        constants$651.X509_ATTRIBUTE_free$FUNC, false
    );
    static final FunctionDescriptor d2i_X509_ATTRIBUTE$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_X509_ATTRIBUTE$MH = RuntimeHelper.downcallHandle(
        "d2i_X509_ATTRIBUTE",
        constants$651.d2i_X509_ATTRIBUTE$FUNC, false
    );
    static final FunctionDescriptor i2d_X509_ATTRIBUTE$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_X509_ATTRIBUTE$MH = RuntimeHelper.downcallHandle(
        "i2d_X509_ATTRIBUTE",
        constants$651.i2d_X509_ATTRIBUTE$FUNC, false
    );
    static final FunctionDescriptor X509_ATTRIBUTE_create$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_ATTRIBUTE_create$MH = RuntimeHelper.downcallHandle(
        "X509_ATTRIBUTE_create",
        constants$651.X509_ATTRIBUTE_create$FUNC, false
    );
    static final FunctionDescriptor X509_EXTENSION_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_EXTENSION_new$MH = RuntimeHelper.downcallHandle(
        "X509_EXTENSION_new",
        constants$651.X509_EXTENSION_new$FUNC, false
    );
    static final FunctionDescriptor X509_EXTENSION_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_EXTENSION_free$MH = RuntimeHelper.downcallHandle(
        "X509_EXTENSION_free",
        constants$651.X509_EXTENSION_free$FUNC, false
    );
}


