// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1037 {

    static final FunctionDescriptor sk_IPAddressOrRange_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_IPAddressOrRange_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_reserve",
        constants$1037.sk_IPAddressOrRange_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_free$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_free",
        constants$1037.sk_IPAddressOrRange_free$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_zero$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_zero",
        constants$1037.sk_IPAddressOrRange_zero$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_IPAddressOrRange_delete$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_delete",
        constants$1037.sk_IPAddressOrRange_delete$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_delete_ptr",
        constants$1037.sk_IPAddressOrRange_delete_ptr$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_push$MH = RuntimeHelper.downcallHandle(
        "sk_IPAddressOrRange_push",
        constants$1037.sk_IPAddressOrRange_push$FUNC, false
    );
}

