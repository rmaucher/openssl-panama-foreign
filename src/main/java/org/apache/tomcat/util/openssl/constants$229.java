// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$229 {

    static final FunctionDescriptor d2i_ASN1_IA5STRING$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASN1_IA5STRING$MH = RuntimeHelper.downcallHandle(
        "d2i_ASN1_IA5STRING",
        constants$229.d2i_ASN1_IA5STRING$FUNC, false
    );
    static final FunctionDescriptor i2d_ASN1_IA5STRING$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASN1_IA5STRING$MH = RuntimeHelper.downcallHandle(
        "i2d_ASN1_IA5STRING",
        constants$229.i2d_ASN1_IA5STRING$FUNC, false
    );
    static final FunctionDescriptor ASN1_GENERALSTRING_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ASN1_GENERALSTRING_new$MH = RuntimeHelper.downcallHandle(
        "ASN1_GENERALSTRING_new",
        constants$229.ASN1_GENERALSTRING_new$FUNC, false
    );
    static final FunctionDescriptor ASN1_GENERALSTRING_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ASN1_GENERALSTRING_free$MH = RuntimeHelper.downcallHandle(
        "ASN1_GENERALSTRING_free",
        constants$229.ASN1_GENERALSTRING_free$FUNC, false
    );
    static final FunctionDescriptor d2i_ASN1_GENERALSTRING$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASN1_GENERALSTRING$MH = RuntimeHelper.downcallHandle(
        "d2i_ASN1_GENERALSTRING",
        constants$229.d2i_ASN1_GENERALSTRING$FUNC, false
    );
    static final FunctionDescriptor i2d_ASN1_GENERALSTRING$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASN1_GENERALSTRING$MH = RuntimeHelper.downcallHandle(
        "i2d_ASN1_GENERALSTRING",
        constants$229.i2d_ASN1_GENERALSTRING$FUNC, false
    );
}


