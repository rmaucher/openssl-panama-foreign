// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$282 {

    static final FunctionDescriptor EVP_EncryptInit$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_EncryptInit$MH = RuntimeHelper.downcallHandle(
        "EVP_EncryptInit",
        constants$282.EVP_EncryptInit$FUNC, false
    );
    static final FunctionDescriptor EVP_EncryptInit_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_EncryptInit_ex$MH = RuntimeHelper.downcallHandle(
        "EVP_EncryptInit_ex",
        constants$282.EVP_EncryptInit_ex$FUNC, false
    );
    static final FunctionDescriptor EVP_EncryptUpdate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_EncryptUpdate$MH = RuntimeHelper.downcallHandle(
        "EVP_EncryptUpdate",
        constants$282.EVP_EncryptUpdate$FUNC, false
    );
    static final FunctionDescriptor EVP_EncryptFinal_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_EncryptFinal_ex$MH = RuntimeHelper.downcallHandle(
        "EVP_EncryptFinal_ex",
        constants$282.EVP_EncryptFinal_ex$FUNC, false
    );
    static final FunctionDescriptor EVP_EncryptFinal$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_EncryptFinal$MH = RuntimeHelper.downcallHandle(
        "EVP_EncryptFinal",
        constants$282.EVP_EncryptFinal$FUNC, false
    );
    static final FunctionDescriptor EVP_DecryptInit$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_DecryptInit$MH = RuntimeHelper.downcallHandle(
        "EVP_DecryptInit",
        constants$282.EVP_DecryptInit$FUNC, false
    );
}


