// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$289 {

    static final FunctionDescriptor EVP_CIPHER_CTX_set_key_length$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_CIPHER_CTX_set_key_length$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_CTX_set_key_length",
        constants$289.EVP_CIPHER_CTX_set_key_length$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_CTX_set_padding$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_CIPHER_CTX_set_padding$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_CTX_set_padding",
        constants$289.EVP_CIPHER_CTX_set_padding$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_CTX_ctrl$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_CIPHER_CTX_ctrl$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_CTX_ctrl",
        constants$289.EVP_CIPHER_CTX_ctrl$FUNC, false
    );
    static final FunctionDescriptor EVP_CIPHER_CTX_rand_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_CIPHER_CTX_rand_key$MH = RuntimeHelper.downcallHandle(
        "EVP_CIPHER_CTX_rand_key",
        constants$289.EVP_CIPHER_CTX_rand_key$FUNC, false
    );
    static final FunctionDescriptor BIO_f_md$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle BIO_f_md$MH = RuntimeHelper.downcallHandle(
        "BIO_f_md",
        constants$289.BIO_f_md$FUNC, false
    );
    static final FunctionDescriptor BIO_f_base64$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle BIO_f_base64$MH = RuntimeHelper.downcallHandle(
        "BIO_f_base64",
        constants$289.BIO_f_base64$FUNC, false
    );
}

