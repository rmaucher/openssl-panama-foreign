// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$286 {

    static final FunctionDescriptor EVP_OpenFinal$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_OpenFinal$MH = RuntimeHelper.downcallHandle(
        "EVP_OpenFinal",
        constants$286.EVP_OpenFinal$FUNC, false
    );
    static final FunctionDescriptor EVP_SealInit$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_SealInit$MH = RuntimeHelper.downcallHandle(
        "EVP_SealInit",
        constants$286.EVP_SealInit$FUNC, false
    );
    static final FunctionDescriptor EVP_SealFinal$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_SealFinal$MH = RuntimeHelper.downcallHandle(
        "EVP_SealFinal",
        constants$286.EVP_SealFinal$FUNC, false
    );
    static final FunctionDescriptor EVP_ENCODE_CTX_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_ENCODE_CTX_new$MH = RuntimeHelper.downcallHandle(
        "EVP_ENCODE_CTX_new",
        constants$286.EVP_ENCODE_CTX_new$FUNC, false
    );
    static final FunctionDescriptor EVP_ENCODE_CTX_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle EVP_ENCODE_CTX_free$MH = RuntimeHelper.downcallHandle(
        "EVP_ENCODE_CTX_free",
        constants$286.EVP_ENCODE_CTX_free$FUNC, false
    );
    static final FunctionDescriptor EVP_ENCODE_CTX_copy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_ENCODE_CTX_copy$MH = RuntimeHelper.downcallHandle(
        "EVP_ENCODE_CTX_copy",
        constants$286.EVP_ENCODE_CTX_copy$FUNC, false
    );
}

