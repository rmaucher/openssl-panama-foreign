// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$344 {

    static final FunctionDescriptor EVP_PKEY_asn1_set_get_priv_key$get_priv_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_get_priv_key$get_priv_key$MH = RuntimeHelper.downcallHandle(
        constants$344.EVP_PKEY_asn1_set_get_priv_key$get_priv_key$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_set_get_priv_key$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_get_priv_key$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_asn1_set_get_priv_key",
        constants$344.EVP_PKEY_asn1_set_get_priv_key$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_set_get_pub_key$get_pub_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_get_pub_key$get_pub_key$MH = RuntimeHelper.downcallHandle(
        constants$344.EVP_PKEY_asn1_set_get_pub_key$get_pub_key$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_asn1_set_get_pub_key$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_asn1_set_get_pub_key$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_asn1_set_get_pub_key",
        constants$344.EVP_PKEY_asn1_set_get_pub_key$FUNC, false
    );
}


