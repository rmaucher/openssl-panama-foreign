// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$496 {

    static final FunctionDescriptor sk_X509_EXTENSION_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_EXTENSION_dup$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_dup",
        constants$496.sk_X509_EXTENSION_dup$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_EXTENSION_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_deep_copy",
        constants$496.sk_X509_EXTENSION_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_EXTENSION_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_set_cmp_func",
        constants$496.sk_X509_EXTENSION_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$496.sk_X509_ATTRIBUTE_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
}

