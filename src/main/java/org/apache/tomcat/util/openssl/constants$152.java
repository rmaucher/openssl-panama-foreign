// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$152 {

    static final FunctionDescriptor BN_bn2binpad$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BN_bn2binpad$MH = RuntimeHelper.downcallHandle(
        "BN_bn2binpad",
        constants$152.BN_bn2binpad$FUNC, false
    );
    static final FunctionDescriptor BN_lebin2bn$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_lebin2bn$MH = RuntimeHelper.downcallHandle(
        "BN_lebin2bn",
        constants$152.BN_lebin2bn$FUNC, false
    );
    static final FunctionDescriptor BN_bn2lebinpad$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BN_bn2lebinpad$MH = RuntimeHelper.downcallHandle(
        "BN_bn2lebinpad",
        constants$152.BN_bn2lebinpad$FUNC, false
    );
    static final FunctionDescriptor BN_mpi2bn$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BN_mpi2bn$MH = RuntimeHelper.downcallHandle(
        "BN_mpi2bn",
        constants$152.BN_mpi2bn$FUNC, false
    );
    static final FunctionDescriptor BN_bn2mpi$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BN_bn2mpi$MH = RuntimeHelper.downcallHandle(
        "BN_bn2mpi",
        constants$152.BN_bn2mpi$FUNC, false
    );
    static final FunctionDescriptor BN_sub$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BN_sub$MH = RuntimeHelper.downcallHandle(
        "BN_sub",
        constants$152.BN_sub$FUNC, false
    );
}


