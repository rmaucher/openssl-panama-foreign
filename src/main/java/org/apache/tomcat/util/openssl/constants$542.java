// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$542 {

    static final FunctionDescriptor sk_X509_LOOKUP_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_LOOKUP_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_X509_LOOKUP_set_cmp_func",
        constants$542.sk_X509_LOOKUP_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$542.sk_X509_OBJECT_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$542.sk_X509_OBJECT_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
}


