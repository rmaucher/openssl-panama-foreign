// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$243 {

    static final FunctionDescriptor ASN1_parse_dump$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle ASN1_parse_dump$MH = RuntimeHelper.downcallHandle(
        "ASN1_parse_dump",
        constants$243.ASN1_parse_dump$FUNC, false
    );
    static final FunctionDescriptor ASN1_tag2str$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ASN1_tag2str$MH = RuntimeHelper.downcallHandle(
        "ASN1_tag2str",
        constants$243.ASN1_tag2str$FUNC, false
    );
    static final FunctionDescriptor ASN1_UNIVERSALSTRING_to_string$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle ASN1_UNIVERSALSTRING_to_string$MH = RuntimeHelper.downcallHandle(
        "ASN1_UNIVERSALSTRING_to_string",
        constants$243.ASN1_UNIVERSALSTRING_to_string$FUNC, false
    );
    static final FunctionDescriptor ASN1_TYPE_set_octetstring$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ASN1_TYPE_set_octetstring$MH = RuntimeHelper.downcallHandle(
        "ASN1_TYPE_set_octetstring",
        constants$243.ASN1_TYPE_set_octetstring$FUNC, false
    );
    static final FunctionDescriptor ASN1_TYPE_get_octetstring$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ASN1_TYPE_get_octetstring$MH = RuntimeHelper.downcallHandle(
        "ASN1_TYPE_get_octetstring",
        constants$243.ASN1_TYPE_get_octetstring$FUNC, false
    );
    static final FunctionDescriptor ASN1_TYPE_set_int_octetstring$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ASN1_TYPE_set_int_octetstring$MH = RuntimeHelper.downcallHandle(
        "ASN1_TYPE_set_int_octetstring",
        constants$243.ASN1_TYPE_set_int_octetstring$FUNC, false
    );
}


