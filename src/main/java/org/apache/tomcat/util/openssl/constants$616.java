// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$616 {

    static final FunctionDescriptor PKCS7_add_signer$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_add_signer$MH = RuntimeHelper.downcallHandle(
        "PKCS7_add_signer",
        constants$616.PKCS7_add_signer$FUNC, false
    );
    static final FunctionDescriptor PKCS7_add_certificate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_add_certificate$MH = RuntimeHelper.downcallHandle(
        "PKCS7_add_certificate",
        constants$616.PKCS7_add_certificate$FUNC, false
    );
    static final FunctionDescriptor PKCS7_add_crl$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_add_crl$MH = RuntimeHelper.downcallHandle(
        "PKCS7_add_crl",
        constants$616.PKCS7_add_crl$FUNC, false
    );
    static final FunctionDescriptor PKCS7_content_new$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PKCS7_content_new$MH = RuntimeHelper.downcallHandle(
        "PKCS7_content_new",
        constants$616.PKCS7_content_new$FUNC, false
    );
    static final FunctionDescriptor PKCS7_dataVerify$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_dataVerify$MH = RuntimeHelper.downcallHandle(
        "PKCS7_dataVerify",
        constants$616.PKCS7_dataVerify$FUNC, false
    );
    static final FunctionDescriptor PKCS7_signatureVerify$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PKCS7_signatureVerify$MH = RuntimeHelper.downcallHandle(
        "PKCS7_signatureVerify",
        constants$616.PKCS7_signatureVerify$FUNC, false
    );
}


