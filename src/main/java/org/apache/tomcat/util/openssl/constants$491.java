// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$491 {

    static final FunctionDescriptor sk_X509_NAME_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_dup$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_dup",
        constants$491.sk_X509_NAME_dup$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_deep_copy",
        constants$491.sk_X509_NAME_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_set_cmp_func",
        constants$491.sk_X509_NAME_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_EXTENSION_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$491.sk_X509_EXTENSION_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
}


