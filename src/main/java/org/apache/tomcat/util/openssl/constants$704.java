// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$704 {

    static final FunctionDescriptor PKCS5_pbe2_set_iv$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS5_pbe2_set_iv$MH = RuntimeHelper.downcallHandle(
        "PKCS5_pbe2_set_iv",
        constants$704.PKCS5_pbe2_set_iv$FUNC, false
    );
    static final FunctionDescriptor PKCS5_pbe2_set_scrypt$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle PKCS5_pbe2_set_scrypt$MH = RuntimeHelper.downcallHandle(
        "PKCS5_pbe2_set_scrypt",
        constants$704.PKCS5_pbe2_set_scrypt$FUNC, false
    );
    static final FunctionDescriptor PKCS5_pbkdf2_set$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle PKCS5_pbkdf2_set$MH = RuntimeHelper.downcallHandle(
        "PKCS5_pbkdf2_set",
        constants$704.PKCS5_pbkdf2_set$FUNC, false
    );
    static final FunctionDescriptor PKCS8_PRIV_KEY_INFO_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle PKCS8_PRIV_KEY_INFO_new$MH = RuntimeHelper.downcallHandle(
        "PKCS8_PRIV_KEY_INFO_new",
        constants$704.PKCS8_PRIV_KEY_INFO_new$FUNC, false
    );
    static final FunctionDescriptor PKCS8_PRIV_KEY_INFO_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle PKCS8_PRIV_KEY_INFO_free$MH = RuntimeHelper.downcallHandle(
        "PKCS8_PRIV_KEY_INFO_free",
        constants$704.PKCS8_PRIV_KEY_INFO_free$FUNC, false
    );
    static final FunctionDescriptor d2i_PKCS8_PRIV_KEY_INFO$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_PKCS8_PRIV_KEY_INFO$MH = RuntimeHelper.downcallHandle(
        "d2i_PKCS8_PRIV_KEY_INFO",
        constants$704.d2i_PKCS8_PRIV_KEY_INFO$FUNC, false
    );
}

