// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$317 {

    static final FunctionDescriptor EVP_chacha20$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_chacha20$MH = RuntimeHelper.downcallHandle(
        "EVP_chacha20",
        constants$317.EVP_chacha20$FUNC, false
    );
    static final FunctionDescriptor EVP_chacha20_poly1305$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_chacha20_poly1305$MH = RuntimeHelper.downcallHandle(
        "EVP_chacha20_poly1305",
        constants$317.EVP_chacha20_poly1305$FUNC, false
    );
    static final FunctionDescriptor EVP_seed_ecb$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_seed_ecb$MH = RuntimeHelper.downcallHandle(
        "EVP_seed_ecb",
        constants$317.EVP_seed_ecb$FUNC, false
    );
    static final FunctionDescriptor EVP_seed_cbc$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_seed_cbc$MH = RuntimeHelper.downcallHandle(
        "EVP_seed_cbc",
        constants$317.EVP_seed_cbc$FUNC, false
    );
    static final FunctionDescriptor EVP_seed_cfb128$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_seed_cfb128$MH = RuntimeHelper.downcallHandle(
        "EVP_seed_cfb128",
        constants$317.EVP_seed_cfb128$FUNC, false
    );
    static final FunctionDescriptor EVP_seed_ofb$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_seed_ofb$MH = RuntimeHelper.downcallHandle(
        "EVP_seed_ofb",
        constants$317.EVP_seed_ofb$FUNC, false
    );
}

