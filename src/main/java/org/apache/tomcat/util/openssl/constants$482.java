// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$482 {

    static final FunctionDescriptor sk_X509_NAME_ENTRY_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_ENTRY_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$482.sk_X509_NAME_ENTRY_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_ENTRY_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_ENTRY_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$482.sk_X509_NAME_ENTRY_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_ENTRY_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_ENTRY_num$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_ENTRY_num",
        constants$482.sk_X509_NAME_ENTRY_num$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_ENTRY_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_NAME_ENTRY_value$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_ENTRY_value",
        constants$482.sk_X509_NAME_ENTRY_value$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_ENTRY_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_ENTRY_new$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_ENTRY_new",
        constants$482.sk_X509_NAME_ENTRY_new$FUNC, false
    );
}


