// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$218 {

    static final FunctionDescriptor ASN1_INTEGER_cmp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_INTEGER_cmp$MH = RuntimeHelper.downcallHandle(
        "ASN1_INTEGER_cmp",
        constants$218.ASN1_INTEGER_cmp$FUNC, false
    );
    static final FunctionDescriptor ASN1_ENUMERATED_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ASN1_ENUMERATED_new$MH = RuntimeHelper.downcallHandle(
        "ASN1_ENUMERATED_new",
        constants$218.ASN1_ENUMERATED_new$FUNC, false
    );
    static final FunctionDescriptor ASN1_ENUMERATED_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ASN1_ENUMERATED_free$MH = RuntimeHelper.downcallHandle(
        "ASN1_ENUMERATED_free",
        constants$218.ASN1_ENUMERATED_free$FUNC, false
    );
    static final FunctionDescriptor d2i_ASN1_ENUMERATED$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASN1_ENUMERATED$MH = RuntimeHelper.downcallHandle(
        "d2i_ASN1_ENUMERATED",
        constants$218.d2i_ASN1_ENUMERATED$FUNC, false
    );
    static final FunctionDescriptor i2d_ASN1_ENUMERATED$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASN1_ENUMERATED$MH = RuntimeHelper.downcallHandle(
        "i2d_ASN1_ENUMERATED",
        constants$218.i2d_ASN1_ENUMERATED$FUNC, false
    );
    static final FunctionDescriptor ASN1_UTCTIME_check$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle ASN1_UTCTIME_check$MH = RuntimeHelper.downcallHandle(
        "ASN1_UTCTIME_check",
        constants$218.ASN1_UTCTIME_check$FUNC, false
    );
}


