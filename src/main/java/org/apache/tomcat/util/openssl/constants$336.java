// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$336 {

    static final FunctionDescriptor EVP_PKEY_asn1_set_private$priv_decode$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_private$priv_decode$MH = RuntimeHelper.downcallHandle(
        constants$336.EVP_PKEY_asn1_set_private$priv_decode$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_set_private$priv_encode$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_private$priv_encode$MH = RuntimeHelper.downcallHandle(
        constants$336.EVP_PKEY_asn1_set_private$priv_encode$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_set_private$priv_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_private$priv_print$MH = RuntimeHelper.downcallHandle(
        constants$336.EVP_PKEY_asn1_set_private$priv_print$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_set_private$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_private$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_asn1_set_private",
        constants$336.EVP_PKEY_asn1_set_private$FUNC, false
    );
}

