// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$356 {

    static final FunctionDescriptor EVP_PKEY_meth_set_copy$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_copy$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_set_copy",
        constants$356.EVP_PKEY_meth_set_copy$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_cleanup$cleanup$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_cleanup$cleanup$MH = RuntimeHelper.downcallHandle(
        constants$356.EVP_PKEY_meth_set_cleanup$cleanup$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_cleanup$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_cleanup$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_set_cleanup",
        constants$356.EVP_PKEY_meth_set_cleanup$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_paramgen$paramgen_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_paramgen$paramgen_init$MH = RuntimeHelper.downcallHandle(
        constants$356.EVP_PKEY_meth_set_paramgen$paramgen_init$FUNC, false
    );
}

