// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$358 {

    static final FunctionDescriptor EVP_PKEY_meth_set_keygen$keygen$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_keygen$keygen$MH = RuntimeHelper.downcallHandle(
        constants$358.EVP_PKEY_meth_set_keygen$keygen$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_keygen$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_keygen$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_set_keygen",
        constants$358.EVP_PKEY_meth_set_keygen$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_sign$sign_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_set_sign$sign_init$MH = RuntimeHelper.downcallHandle(
        constants$358.EVP_PKEY_meth_set_sign$sign_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_set_sign$sign$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EVP_PKEY_meth_set_sign$sign$MH = RuntimeHelper.downcallHandle(
        constants$358.EVP_PKEY_meth_set_sign$sign$FUNC, false
    );
}

