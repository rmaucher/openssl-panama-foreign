// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$369 {

    static final FunctionDescriptor EVP_PKEY_meth_get_init$pinit$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_init$pinit$MH = RuntimeHelper.downcallHandle(
        constants$369.EVP_PKEY_meth_get_init$pinit$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_init$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_init$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_get_init",
        constants$369.EVP_PKEY_meth_get_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_copy$pcopy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_copy$pcopy$MH = RuntimeHelper.downcallHandle(
        constants$369.EVP_PKEY_meth_get_copy$pcopy$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_copy$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_copy$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_get_copy",
        constants$369.EVP_PKEY_meth_get_copy$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_cleanup$pcleanup$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
}

