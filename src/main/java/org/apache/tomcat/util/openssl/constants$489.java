// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$489 {

    static final FunctionDescriptor sk_X509_NAME_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_delete_ptr",
        constants$489.sk_X509_NAME_delete_ptr$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_push$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_push",
        constants$489.sk_X509_NAME_push$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_unshift",
        constants$489.sk_X509_NAME_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_pop$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_pop",
        constants$489.sk_X509_NAME_pop$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_shift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_shift",
        constants$489.sk_X509_NAME_shift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_pop_free",
        constants$489.sk_X509_NAME_pop_free$FUNC, false
    );
}


