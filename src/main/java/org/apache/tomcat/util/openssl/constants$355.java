// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$355 {

    static final FunctionDescriptor EVP_PKEY_CTX_get_keygen_info$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_PKEY_CTX_get_keygen_info$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_CTX_get_keygen_info",
        constants$355.EVP_PKEY_CTX_get_keygen_info$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_init$init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_init$init$MH = RuntimeHelper.downcallHandle(
        constants$355.EVP_PKEY_meth_set_init$init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_init$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_init$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_set_init",
        constants$355.EVP_PKEY_meth_set_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_copy$copy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_copy$copy$MH = RuntimeHelper.downcallHandle(
        constants$355.EVP_PKEY_meth_set_copy$copy$FUNC, false
    );
}

