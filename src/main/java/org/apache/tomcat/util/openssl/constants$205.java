// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$205 {

    static final FunctionDescriptor i2d_ASN1_SEQUENCE_ANY$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASN1_SEQUENCE_ANY$MH = RuntimeHelper.downcallHandle(
        "i2d_ASN1_SEQUENCE_ANY",
        constants$205.i2d_ASN1_SEQUENCE_ANY$FUNC, false
    );
    static final FunctionDescriptor d2i_ASN1_SET_ANY$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASN1_SET_ANY$MH = RuntimeHelper.downcallHandle(
        "d2i_ASN1_SET_ANY",
        constants$205.d2i_ASN1_SET_ANY$FUNC, false
    );
    static final FunctionDescriptor i2d_ASN1_SET_ANY$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASN1_SET_ANY$MH = RuntimeHelper.downcallHandle(
        "i2d_ASN1_SET_ANY",
        constants$205.i2d_ASN1_SET_ANY$FUNC, false
    );
    static final FunctionDescriptor ASN1_TYPE_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ASN1_TYPE_new$MH = RuntimeHelper.downcallHandle(
        "ASN1_TYPE_new",
        constants$205.ASN1_TYPE_new$FUNC, false
    );
    static final FunctionDescriptor ASN1_TYPE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ASN1_TYPE_free$MH = RuntimeHelper.downcallHandle(
        "ASN1_TYPE_free",
        constants$205.ASN1_TYPE_free$FUNC, false
    );
    static final FunctionDescriptor d2i_ASN1_TYPE$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASN1_TYPE$MH = RuntimeHelper.downcallHandle(
        "d2i_ASN1_TYPE",
        constants$205.d2i_ASN1_TYPE$FUNC, false
    );
}


