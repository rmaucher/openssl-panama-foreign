// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$12 {

    static final FunctionDescriptor SSL_pending$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_pending$MH = RuntimeHelper.downcallHandle(
        "SSL_pending",
        constants$12.SSL_pending$FUNC, false
    );
    static final FunctionDescriptor SSL_set_bio$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_set_bio$MH = RuntimeHelper.downcallHandle(
        "SSL_set_bio",
        constants$12.SSL_set_bio$FUNC, false
    );
    static final FunctionDescriptor SSL_set_cipher_list$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_set_cipher_list$MH = RuntimeHelper.downcallHandle(
        "SSL_set_cipher_list",
        constants$12.SSL_set_cipher_list$FUNC, false
    );
    static final FunctionDescriptor SSL_set_verify$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_set_verify$MH = RuntimeHelper.downcallHandle(
        "SSL_set_verify",
        constants$12.SSL_set_verify$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_use_certificate_chain_file$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_use_certificate_chain_file$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_use_certificate_chain_file",
        constants$12.SSL_CTX_use_certificate_chain_file$FUNC, false
    );
    static final FunctionDescriptor SSL_load_client_CA_file$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_load_client_CA_file$MH = RuntimeHelper.downcallHandle(
        "SSL_load_client_CA_file",
        constants$12.SSL_load_client_CA_file$FUNC, false
    );
}


