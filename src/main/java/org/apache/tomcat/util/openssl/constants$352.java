// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$352 {

    static final FunctionDescriptor EVP_PKEY_encrypt_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_encrypt_init$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_encrypt_init",
        constants$352.EVP_PKEY_encrypt_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_encrypt$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EVP_PKEY_encrypt$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_encrypt",
        constants$352.EVP_PKEY_encrypt$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_decrypt_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_decrypt_init$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_decrypt_init",
        constants$352.EVP_PKEY_decrypt_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_decrypt$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EVP_PKEY_decrypt$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_decrypt",
        constants$352.EVP_PKEY_decrypt$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_derive_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_derive_init$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_derive_init",
        constants$352.EVP_PKEY_derive_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_derive_set_peer$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_derive_set_peer$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_derive_set_peer",
        constants$352.EVP_PKEY_derive_set_peer$FUNC, false
    );
}


