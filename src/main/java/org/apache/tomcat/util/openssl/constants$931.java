// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$931 {

    static final FunctionDescriptor X509V3_EXT_R2I$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509V3_EXT_R2I$MH = RuntimeHelper.downcallHandle(
        constants$931.X509V3_EXT_R2I$FUNC, false
    );
    static final FunctionDescriptor sk_X509V3_EXT_METHOD_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509V3_EXT_METHOD_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$931.sk_X509V3_EXT_METHOD_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509V3_EXT_METHOD_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509V3_EXT_METHOD_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$931.sk_X509V3_EXT_METHOD_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509V3_EXT_METHOD_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
}

