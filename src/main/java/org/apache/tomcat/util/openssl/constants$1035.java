// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1035 {

    static final FunctionDescriptor i2d_ASIdentifiers$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ASIdentifiers$MH = RuntimeHelper.downcallHandle(
        "i2d_ASIdentifiers",
        constants$1035.i2d_ASIdentifiers$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$1035.sk_IPAddressOrRange_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_IPAddressOrRange_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$1035.sk_IPAddressOrRange_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_IPAddressOrRange_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
}


