// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$403 {

    static final FunctionDescriptor EC_KEY_oct2priv$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EC_KEY_oct2priv$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_oct2priv",
        constants$403.EC_KEY_oct2priv$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_priv2oct$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle EC_KEY_priv2oct$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_priv2oct",
        constants$403.EC_KEY_priv2oct$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_priv2buf$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_priv2buf$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_priv2buf",
        constants$403.EC_KEY_priv2buf$FUNC, false
    );
    static final FunctionDescriptor d2i_ECPrivateKey$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ECPrivateKey$MH = RuntimeHelper.downcallHandle(
        "d2i_ECPrivateKey",
        constants$403.d2i_ECPrivateKey$FUNC, false
    );
    static final FunctionDescriptor i2d_ECPrivateKey$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ECPrivateKey$MH = RuntimeHelper.downcallHandle(
        "i2d_ECPrivateKey",
        constants$403.i2d_ECPrivateKey$FUNC, false
    );
    static final FunctionDescriptor d2i_ECParameters$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ECParameters$MH = RuntimeHelper.downcallHandle(
        "d2i_ECParameters",
        constants$403.d2i_ECParameters$FUNC, false
    );
}

