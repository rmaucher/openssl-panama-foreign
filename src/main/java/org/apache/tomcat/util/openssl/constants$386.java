// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$386 {

    static final FunctionDescriptor EC_GROUP_get_cofactor$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get_cofactor$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get_cofactor",
        constants$386.EC_GROUP_get_cofactor$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_get0_cofactor$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get0_cofactor$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get0_cofactor",
        constants$386.EC_GROUP_get0_cofactor$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_set_curve_name$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EC_GROUP_set_curve_name$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_set_curve_name",
        constants$386.EC_GROUP_set_curve_name$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_get_curve_name$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get_curve_name$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get_curve_name",
        constants$386.EC_GROUP_get_curve_name$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_set_asn1_flag$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EC_GROUP_set_asn1_flag$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_set_asn1_flag",
        constants$386.EC_GROUP_set_asn1_flag$FUNC, false
    );
    static final FunctionDescriptor EC_GROUP_get_asn1_flag$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EC_GROUP_get_asn1_flag$MH = RuntimeHelper.downcallHandle(
        "EC_GROUP_get_asn1_flag",
        constants$386.EC_GROUP_get_asn1_flag$FUNC, false
    );
}

