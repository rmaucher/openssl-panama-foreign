// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$267 {

    static final FunctionDescriptor EVP_CIPHER_meth_set_iv_length$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_CIPHER_meth_set_iv_length$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_meth_set_iv_length",
        constants$267.EVP_CIPHER_meth_set_iv_length$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_meth_set_flags$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EVP_CIPHER_meth_set_flags$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_meth_set_flags",
        constants$267.EVP_CIPHER_meth_set_flags$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_meth_set_impl_ctx_size$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_CIPHER_meth_set_impl_ctx_size$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_meth_set_impl_ctx_size",
        constants$267.EVP_CIPHER_meth_set_impl_ctx_size$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_meth_set_init$init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_CIPHER_meth_set_init$init$MH = RuntimeHelper.downcallHandle(
        constants$267.EVP_CIPHER_meth_set_init$init$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_meth_set_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_CIPHER_meth_set_init$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_meth_set_init",
        constants$267.EVP_CIPHER_meth_set_init$FUNC, false
    );
}

