// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$215 {

    static final FunctionDescriptor ASN1_STRING_get0_data$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_STRING_get0_data$MH = RuntimeHelper.downcallHandle(
        "ASN1_STRING_get0_data",
        constants$215.ASN1_STRING_get0_data$FUNC, false
    );
    static final FunctionDescriptor ASN1_BIT_STRING_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ASN1_BIT_STRING_new$MH = RuntimeHelper.downcallHandle(
        "ASN1_BIT_STRING_new",
        constants$215.ASN1_BIT_STRING_new$FUNC, false
    );
    static final FunctionDescriptor ASN1_BIT_STRING_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ASN1_BIT_STRING_free$MH = RuntimeHelper.downcallHandle(
        "ASN1_BIT_STRING_free",
        constants$215.ASN1_BIT_STRING_free$FUNC, false
    );
    static final FunctionDescriptor d2i_ASN1_BIT_STRING$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASN1_BIT_STRING$MH = RuntimeHelper.downcallHandle(
        "d2i_ASN1_BIT_STRING",
        constants$215.d2i_ASN1_BIT_STRING$FUNC, false
    );
    static final FunctionDescriptor i2d_ASN1_BIT_STRING$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASN1_BIT_STRING$MH = RuntimeHelper.downcallHandle(
        "i2d_ASN1_BIT_STRING",
        constants$215.i2d_ASN1_BIT_STRING$FUNC, false
    );
    static final FunctionDescriptor ASN1_BIT_STRING_set$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ASN1_BIT_STRING_set$MH = RuntimeHelper.downcallHandle(
        "ASN1_BIT_STRING_set",
        constants$215.ASN1_BIT_STRING_set$FUNC, false
    );
}

