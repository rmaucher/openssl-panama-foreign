/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net.openssl.panama;

import jdk.incubator.foreign.CLinker;
import jdk.incubator.foreign.FunctionDescriptor;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.NativeSymbol;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SegmentAllocator;
import jdk.incubator.foreign.ValueLayout;

import static org.apache.tomcat.util.openssl.openssl_h.*;

import java.io.File;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.ref.Cleaner;
import java.lang.ref.Cleaner.Cleanable;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.Constants;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfig.CertificateVerification;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.openssl.OpenSSLConf;
import org.apache.tomcat.util.net.openssl.OpenSSLConfCmd;
import org.apache.tomcat.util.res.StringManager;

public class OpenSSLContext implements org.apache.tomcat.util.net.SSLContext {

    private static final Log log = LogFactory.getLog(OpenSSLContext.class);

    private static final StringManager netSm = StringManager.getManager(AbstractEndpoint.class);
    private static final StringManager sm = StringManager.getManager(OpenSSLContext.class);

    private static final String defaultProtocol = "TLS";

    private static final int SSL_AIDX_RSA     = 0;
    private static final int SSL_AIDX_DSA     = 1;
    private static final int SSL_AIDX_ECC     = 3;
    private static final int SSL_AIDX_MAX     = 4;

    public static final int SSL_PROTOCOL_NONE  = 0;
    public static final int SSL_PROTOCOL_SSLV2 = (1<<0);
    public static final int SSL_PROTOCOL_SSLV3 = (1<<1);
    public static final int SSL_PROTOCOL_TLSV1 = (1<<2);
    public static final int SSL_PROTOCOL_TLSV1_1 = (1<<3);
    public static final int SSL_PROTOCOL_TLSV1_2 = (1<<4);
    public static final int SSL_PROTOCOL_TLSV1_3 = (1<<5);
    public static final int SSL_PROTOCOL_ALL = (SSL_PROTOCOL_TLSV1 | SSL_PROTOCOL_TLSV1_1 | SSL_PROTOCOL_TLSV1_2 |
            SSL_PROTOCOL_TLSV1_3);

    public static final int OCSP_STATUS_OK      = 0;
    public static final int OCSP_STATUS_REVOKED = 1;
    public static final int OCSP_STATUS_UNKNOWN = 2;

    private static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----\n";
    private static final Object END_KEY = "\n-----END PRIVATE KEY-----";

    private static final byte[] HTTP_11_PROTOCOL =
            new byte[] { 'h', 't', 't', 'p', '/', '1', '.', '1' };

    private static final byte[] DEFAULT_SESSION_ID_CONTEXT =
            new byte[] { 'd', 'e', 'f', 'a', 'u', 'l', 't' };

    static final CertificateFactory X509_CERT_FACTORY;
    static {
        try {
            X509_CERT_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(sm.getString("openssl.X509FactoryError"), e);
        }
    }

    private static final MethodHandle openSSLCallbackVerifyHandle;
    private static final MethodHandle openSSLCallbackPasswordHandle;
    private static final MethodHandle openSSLCallbackCertVerifyHandle;
    private static final MethodHandle openSSLCallbackAlpnSelectProtoHandle;
    private static final MethodHandle openSSLCallbackTmpDHHandle;

    static {
        MethodHandles.Lookup lookup = MethodHandles.lookup();
        try {
            openSSLCallbackVerifyHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackVerify",
                    MethodType.methodType(int.class, int.class, MemoryAddress.class));
            openSSLCallbackPasswordHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackPassword",
                    MethodType.methodType(int.class, MemoryAddress.class, int.class, int.class, MemoryAddress.class));
            openSSLCallbackCertVerifyHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackCertVerify",
                    MethodType.methodType(int.class, MemoryAddress.class, MemoryAddress.class));
            openSSLCallbackAlpnSelectProtoHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackAlpnSelectProto",
                    MethodType.methodType(int.class, MemoryAddress.class, MemoryAddress.class,
                            MemoryAddress.class, MemoryAddress.class, int.class, MemoryAddress.class));
            openSSLCallbackTmpDHHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackTmpDH",
                    MethodType.methodType(long.class/*MemoryAddress.class*/, MemoryAddress.class, int.class, int.class));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /*
    { BN_get_rfc3526_prime_8192, NULL, 6145 },
    { BN_get_rfc3526_prime_6144, NULL, 4097 },
    { BN_get_rfc3526_prime_4096, NULL, 3073 },
    { BN_get_rfc3526_prime_3072, NULL, 2049 },
    { BN_get_rfc3526_prime_2048, NULL, 1025 },
    { BN_get_rfc2409_prime_1024, NULL, 0 }
     */
    private static final class DHParam {
        private final MemoryAddress dh;
        private final int min;
        private DHParam(MemoryAddress dh, int min) {
            this.dh = dh;
            this.min = min;
        }
    }
    private static final DHParam[] dhParameters = new DHParam[6];

    static {
        var dh = DH_new();
        var p = BN_get_rfc3526_prime_8192(MemoryAddress.NULL);
        var g = BN_new();
        BN_set_word(g, 2);
        DH_set0_pqg(dh, p, MemoryAddress.NULL, g);
        dhParameters[0] = new DHParam(dh, 6145);
        dh = DH_new();
        p = BN_get_rfc3526_prime_6144(MemoryAddress.NULL);
        g = BN_new();
        BN_set_word(g, 2);
        DH_set0_pqg(dh, p, MemoryAddress.NULL, g);
        dhParameters[1] = new DHParam(dh, 4097);
        dh = DH_new();
        p = BN_get_rfc3526_prime_4096(MemoryAddress.NULL);
        g = BN_new();
        BN_set_word(g, 2);
        DH_set0_pqg(dh, p, MemoryAddress.NULL, g);
        dhParameters[2] = new DHParam(dh, 3073);
        dh = DH_new();
        p = BN_get_rfc3526_prime_3072(MemoryAddress.NULL);
        g = BN_new();
        BN_set_word(g, 2);
        DH_set0_pqg(dh, p, MemoryAddress.NULL, g);
        dhParameters[3] = new DHParam(dh, 2049);
        dh = DH_new();
        p = BN_get_rfc3526_prime_2048(MemoryAddress.NULL);
        g = BN_new();
        BN_set_word(g, 2);
        DH_set0_pqg(dh, p, MemoryAddress.NULL, g);
        dhParameters[4] = new DHParam(dh, 1025);
        dh = DH_new();
        p = BN_get_rfc2409_prime_1024(MemoryAddress.NULL);
        g = BN_new();
        BN_set_word(g, 2);
        DH_set0_pqg(dh, p, MemoryAddress.NULL, g);
        dhParameters[5] = new DHParam(dh, 0);
    }

    private static final Cleaner cleaner = Cleaner.create();

    private final SSLHostConfig sslHostConfig;
    private final SSLHostConfigCertificate certificate;
    private final List<String> negotiableProtocols;

    private int certificateVerifyMode = -1;

    private OpenSSLSessionContext sessionContext;
    private X509TrustManager x509TrustManager;
    private String enabledProtocol;
    private boolean initialized = false;

    private boolean noOcspCheck = false;

    private final OpenSSLState state;
    private final Cleanable cleanable;

    private static String[] getCiphers(MemoryAddress sslCtx) {
        MemoryAddress sk = SSL_CTX_get_ciphers(sslCtx);
        int len = OPENSSL_sk_num(sk);
        if (len <= 0) {
            return null;
        }
        ArrayList<String> ciphers = new ArrayList<>(len);
        for (int i = 0; i < len; i++) {
            MemoryAddress cipher = OPENSSL_sk_value(sk, i);
            MemoryAddress cipherName = SSL_CIPHER_get_name(cipher);
            ciphers.add(cipherName.getUtf8String(0));
        }
        return ciphers.toArray(new String[0]);
    }

    public OpenSSLContext(SSLHostConfigCertificate certificate, List<String> negotiableProtocols)
            throws SSLException {

        // Check that OpenSSL was initialized
        if (!OpenSSLStatus.isInitialized()) {
            try {
                OpenSSLLifecycleListener.init();
            } catch (Exception e) {
                throw new SSLException(e);
            }
        }

        this.sslHostConfig = certificate.getSSLHostConfig();
        this.certificate = certificate;
        ResourceScope scope = ResourceScope.newSharedScope();

        MemoryAddress ctx = MemoryAddress.NULL;
        MemoryAddress cctx = MemoryAddress.NULL;
        NativeSymbol openSSLCallbackPassword = null;
        boolean success = false;
        try {
            // Create OpenSSLConfCmd context if used
            OpenSSLConf openSslConf = sslHostConfig.getOpenSslConf();
            if (openSslConf != null) {
                var allocator = SegmentAllocator.nativeAllocator(scope);
                try {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("openssl.makeConf"));
                    }
                    cctx = SSL_CONF_CTX_new();
                    long errCode = ERR_get_error();
                    if (errCode != 0) {
                        var buf = allocator.allocateArray(ValueLayout.JAVA_BYTE, new byte[128]);
                        ERR_error_string(errCode, buf);
                        log.error(sm.getString("openssl.errorLoadingCertificate", buf.getUtf8String(0)));
                    }
                    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE() |
                            SSL_CONF_FLAG_SERVER() |
                            SSL_CONF_FLAG_CERTIFICATE() |
                            SSL_CONF_FLAG_SHOW_ERRORS());
                } catch (Exception e) {
                    throw new SSLException(sm.getString("openssl.errMakeConf"), e);
                }
            }

            // SSL protocol
            ctx = SSL_CTX_new(TLS_server_method());

            int protocol = SSL_PROTOCOL_NONE;
            for (String enabledProtocol : sslHostConfig.getEnabledProtocols()) {
                if (Constants.SSL_PROTO_SSLv2Hello.equalsIgnoreCase(enabledProtocol)) {
                    // NO-OP. OpenSSL always supports SSLv2Hello
                } else if (Constants.SSL_PROTO_SSLv2.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_SSLV2;
                } else if (Constants.SSL_PROTO_SSLv3.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_SSLV3;
                } else if (Constants.SSL_PROTO_TLSv1.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_TLSV1;
                } else if (Constants.SSL_PROTO_TLSv1_1.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_TLSV1_1;
                } else if (Constants.SSL_PROTO_TLSv1_2.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_TLSV1_2;
                } else if (Constants.SSL_PROTO_TLSv1_3.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_TLSV1_3;
                } else if (Constants.SSL_PROTO_ALL.equalsIgnoreCase(enabledProtocol)) {
                    protocol |= SSL_PROTOCOL_ALL;
                } else {
                    // Should not happen since filtering to build
                    // enabled protocols removes invalid values.
                    throw new Exception(netSm.getString(
                            "endpoint.apr.invalidSslProtocol", enabledProtocol));
                }
            }
            // Set maximum and minimum protocol versions
            int prot = SSL2_VERSION();
            if ((protocol & SSL_PROTOCOL_TLSV1_3) > 0) {
                prot = TLS1_3_VERSION();
            } else if ((protocol & SSL_PROTOCOL_TLSV1_2) > 0) {
                prot = TLS1_2_VERSION();
            } else if ((protocol & SSL_PROTOCOL_TLSV1_1) > 0) {
                prot = TLS1_1_VERSION();
            } else if ((protocol & SSL_PROTOCOL_TLSV1) > 0) {
                prot = TLS1_VERSION();
            } else if ((protocol & SSL_PROTOCOL_SSLV3) > 0) {
                prot = SSL3_VERSION();
            }
            // # define SSL_CTX_set_max_proto_version(ctx, version) \
            //          SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION(), prot, MemoryAddress.NULL);
            if (prot == TLS1_3_VERSION() && (protocol & SSL_PROTOCOL_TLSV1_2) > 0) {
                prot = TLS1_2_VERSION();
            }
            if (prot == TLS1_2_VERSION() && (protocol & SSL_PROTOCOL_TLSV1_1) > 0) {
                prot = TLS1_1_VERSION();
            }
            if (prot == TLS1_1_VERSION() && (protocol & SSL_PROTOCOL_TLSV1) > 0) {
                prot = TLS1_VERSION();
            }
            if (prot == TLS1_VERSION() && (protocol & SSL_PROTOCOL_SSLV3) > 0) {
                prot = SSL3_VERSION();
            }
            //# define SSL_CTX_set_min_proto_version(ctx, version) \
            //         SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION(), prot, MemoryAddress.NULL);

            // Disable compression, usually unsafe
            SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION());

            // Disallow a session from being resumed during a renegotiation,
            // so that an acceptable cipher suite can be negotiated.
            SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION());

            SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE());
            SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE());
            // Option for SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION ?
            // Default session context id and cache size
            // # define SSL_CTX_sess_set_cache_size(ctx,t) \
            //          SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE(), 256, MemoryAddress.NULL);
            // Session cache is disabled by default
            // # define SSL_CTX_set_session_cache_mode(ctx,m) \
            //          SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE(), SSL_SESS_CACHE_OFF(), MemoryAddress.NULL);
            // Longer session timeout
            SSL_CTX_set_timeout(ctx, 14400);

            // From SSLContext.make, possibly set ssl_callback_ServerNameIndication
            // From SSLContext.make, possibly set ssl_callback_ClientHello
            // Probably not needed

            // Set int pem_password_cb(char *buf, int size, int rwflag, void *u) callback
            MethodHandle boundOpenSSLCallbackPasswordHandle = openSSLCallbackPasswordHandle.bindTo(this);
            openSSLCallbackPassword = CLinker.systemCLinker().upcallStub(boundOpenSSLCallbackPasswordHandle,
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT, ValueLayout.ADDRESS), scope);
            SSL_CTX_set_default_passwd_cb(ctx, openSSLCallbackPassword);

            this.negotiableProtocols = negotiableProtocols;

            success = true;
        } catch(Exception e) {
            throw new SSLException(sm.getString("openssl.errorSSLCtxInit"), e);
        } finally {
            state = new OpenSSLState(scope, cctx, ctx, openSSLCallbackPassword);
            /*
             * When an SSLHostConfig is replaced at runtime, it is not possible to
             * call destroy() on the associated OpenSSLContext since it is likely
             * that there will be in-progress connections using the OpenSSLContext.
             * A reference chain has been deliberately established (see
             * OpenSSLSessionContext) to ensure that the OpenSSLContext remains
             * ineligible for GC while those connections are alive. Once those
             * connections complete, the OpenSSLContext will become eligible for GC
             * and this method will ensure that the associated native resources are
             * cleaned up.
             */
            cleanable = cleaner.register(this, state);

            if (!success) {
                destroy();
            }
        }
    }


    public String getEnabledProtocol() {
        return enabledProtocol;
    }


    public void setEnabledProtocol(String protocol) {
        enabledProtocol = (protocol == null) ? defaultProtocol : protocol;
    }


    @Override
    public synchronized void destroy() {
        cleanable.clean();
    }


    private boolean checkConf(OpenSSLConf conf) throws Exception {
        boolean result = true;
        OpenSSLConfCmd cmd;
        String name;
        String value;
        int rc;
        for (OpenSSLConfCmd command : conf.getCommands()) {
            cmd = command;
            name = cmd.getName();
            value = cmd.getValue();
            if (name == null) {
                log.error(sm.getString("opensslconf.noCommandName", value));
                result = false;
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("opensslconf.checkCommand", name, value));
            }
            try (var scope = ResourceScope.newConfinedScope()) {
                // rc = SSLConf.check(cctx, name, value);
                if (name.equals("NO_OCSP_CHECK")) {
                    rc = 1;
                } else {
                    var allocator = SegmentAllocator.nativeAllocator(scope);
                    int code = SSL_CONF_cmd_value_type(state.cctx, allocator.allocateUtf8String(name));
                    rc = 1;
                    long errCode = ERR_get_error();
                    if (errCode != 0) {
                        var buf = allocator.allocateArray(ValueLayout.JAVA_BYTE, new byte[128]);
                        ERR_error_string(errCode, buf);
                        log.error(sm.getString("opensslconf.checkFailed", buf.getUtf8String(0)));
                        rc = 0;
                    }
                    if (code == SSL_CONF_TYPE_UNKNOWN()) {
                        log.error(sm.getString("opensslconf.typeUnknown", name));
                        rc = 0;
                    }
                    if (code == SSL_CONF_TYPE_FILE()) {
                        // Check file
                        File file = new File(value);
                        if (!file.isFile() && !file.canRead()) {
                            log.error(sm.getString("opensslconf.badFile", name, value));
                            rc = 0;
                        }
                    }
                    if (code == SSL_CONF_TYPE_DIR()) {
                        // Check dir
                        File file = new File(value);
                        if (!file.isDirectory()) {
                            log.error(sm.getString("opensslconf.badDirectory", name, value));
                            rc = 0;
                        }
                    }
                }
            } catch (Exception e) {
                log.error(sm.getString("opensslconf.checkFailed", e.getLocalizedMessage()));
                return false;
            }
            if (rc <= 0) {
                log.error(sm.getString("opensslconf.failedCommand", name, value,
                        Integer.toString(rc)));
                result = false;
            } else if (log.isDebugEnabled()) {
                log.debug(sm.getString("opensslconf.resultCommand", name, value,
                        Integer.toString(rc)));
            }
        }
        if (!result) {
            log.error(sm.getString("opensslconf.checkFailed"));
        }
        return result;
    }


    private boolean applyConf(OpenSSLConf conf) throws Exception {
        boolean result = true;
        // SSLConf.assign(cctx, ctx);
        SSL_CONF_CTX_set_ssl_ctx(state.cctx, state.ctx);
        OpenSSLConfCmd cmd;
        String name;
        String value;
        int rc;
        for (OpenSSLConfCmd command : conf.getCommands()) {
            cmd = command;
            name = cmd.getName();
            value = cmd.getValue();
            if (name == null) {
                log.error(sm.getString("opensslconf.noCommandName", value));
                result = false;
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("opensslconf.applyCommand", name, value));
            }
            try (var scope = ResourceScope.newConfinedScope()) {
                // rc = SSLConf.apply(cctx, name, value);
                if (name.equals("NO_OCSP_CHECK")) {
                    noOcspCheck = Boolean.valueOf(value);
                    rc = 1;
                } else {
                    var allocator = SegmentAllocator.nativeAllocator(scope);
                    rc = SSL_CONF_cmd(state.cctx, allocator.allocateUtf8String(name),
                            allocator.allocateUtf8String(value));
                    long errCode = ERR_get_error();
                    if (rc <= 0 || errCode != 0) {
                        var buf = allocator.allocateArray(ValueLayout.JAVA_BYTE, new byte[128]);
                        ERR_error_string(errCode, buf);
                        log.error(sm.getString("opensslconf.commandError", name, value, buf.getUtf8String(0)));
                        rc = 0;
                    }
                }
            } catch (Exception e) {
                log.error(sm.getString("opensslconf.applyFailed"));
                return false;
            }
            if (rc <= 0) {
                log.error(sm.getString("opensslconf.failedCommand", name, value,
                        Integer.toString(rc)));
                result = false;
            } else if (log.isDebugEnabled()) {
                log.debug(sm.getString("opensslconf.resultCommand", name, value,
                        Integer.toString(rc)));
            }
        }
        // rc = SSLConf.finish(cctx);
        rc = SSL_CONF_CTX_finish(state.cctx);
        if (rc <= 0) {
            log.error(sm.getString("opensslconf.finishFailed", Integer.toString(rc)));
            result = false;
        }
        if (!result) {
            log.error(sm.getString("opensslconf.applyFailed"));
        }
        return result;
    }

    private static final int OPTIONAL_NO_CA = 3;

    /**
     * Setup the SSL_CTX.
     *
     * @param kms Must contain a KeyManager of the type
     *            {@code OpenSSLKeyManager}
     * @param tms Must contain a TrustManager of the type
     *            {@code X509TrustManager}
     * @param sr Is not used for this implementation.
     */
    @Override
    public synchronized void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) {
        if (initialized) {
            log.warn(sm.getString("openssl.doubleInit"));
            return;
        }
        try {
            if (sslHostConfig.getInsecureRenegotiation()) {
                SSL_CTX_set_options(state.ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION());
            } else {
                SSL_CTX_clear_options(state.ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION());
            }

            // Use server's preference order for ciphers (rather than
            // client's)
            if (sslHostConfig.getHonorCipherOrder()) {
                SSL_CTX_set_options(state.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE());
            } else {
                SSL_CTX_clear_options(state.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE());
            }

            // Disable compression if requested
            if (sslHostConfig.getDisableCompression()) {
                SSL_CTX_set_options(state.ctx, SSL_OP_NO_COMPRESSION());
            } else {
                SSL_CTX_clear_options(state.ctx, SSL_OP_NO_COMPRESSION());
            }

            // Disable TLS Session Tickets (RFC4507) to protect perfect forward secrecy
            if (sslHostConfig.getDisableSessionTickets()) {
                SSL_CTX_set_options(state.ctx, SSL_OP_NO_TICKET());
            } else {
                SSL_CTX_clear_options(state.ctx, SSL_OP_NO_TICKET());
            }

            // List the ciphers that the client is permitted to negotiate
            if (SSL_CTX_set_cipher_list(state.ctx,
                    SegmentAllocator.nativeAllocator(state.scope).allocateUtf8String(sslHostConfig.getCiphers())) <= 0) {
                log.warn(sm.getString("engine.failedCipherSuite", sslHostConfig.getCiphers()));
            }

            if (certificate.getCertificateFile() == null) {
                certificate.setCertificateKeyManager(OpenSSLUtil.chooseKeyManager(kms));
            }

            addCertificate(certificate);

            // Client certificate verification
            int value = 0;
            switch (sslHostConfig.getCertificateVerification()) {
            case NONE:
                value = SSL_VERIFY_NONE();
                break;
            case OPTIONAL:
                value = SSL_VERIFY_PEER();
                break;
            case OPTIONAL_NO_CA:
                value = OPTIONAL_NO_CA;
                break;
            case REQUIRED:
                value = SSL_VERIFY_FAIL_IF_NO_PEER_CERT();
                break;
            }
            certificateVerifyMode = value;

            // SSLContext.setVerify(state.ctx, value, sslHostConfig.getCertificateVerificationDepth());
            if (SSL_CTX_set_default_verify_paths(state.ctx) > 0) {
                var store = SSL_CTX_get_cert_store(state.ctx);
                X509_STORE_set_flags(store, 0);
            }

            // Set int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) callback
            MethodHandle boundOpenSSLCallbackVerifyHandle = openSSLCallbackVerifyHandle.bindTo(this);
            NativeSymbol openSSLCallbackVerify = CLinker.systemCLinker().upcallStub(boundOpenSSLCallbackVerifyHandle,
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), state.scope);
            SSL_CTX_set_verify(state.ctx, value, openSSLCallbackVerify);

            // Trust and certificate verification
            try (var scope = ResourceScope.newConfinedScope()) {
                var allocator = SegmentAllocator.nativeAllocator(scope);
                if (tms != null) {
                    // Client certificate verification based on custom trust managers
                    x509TrustManager = chooseTrustManager(tms);
                    MethodHandle boundOpenSSLCallbackCertVerifyHandle = openSSLCallbackCertVerifyHandle.bindTo(this);
                    NativeSymbol openSSLCallbackCertVerify = CLinker.systemCLinker().upcallStub(boundOpenSSLCallbackCertVerifyHandle,
                            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS), state.scope);
                    SSL_CTX_set_cert_verify_callback(state.ctx, openSSLCallbackCertVerify, MemoryAddress.NULL);

                    // Pass along the DER encoded certificates of the accepted client
                    // certificate issuers, so that their subjects can be presented
                    // by the server during the handshake to allow the client choosing
                    // an acceptable certificate
                    for (X509Certificate caCert : x509TrustManager.getAcceptedIssuers()) {
                        //SSLContext.addClientCACertificateRaw(state.ctx, caCert.getEncoded());
                        var rawCACertificate = allocator.allocateArray(ValueLayout.JAVA_BYTE, caCert.getEncoded());
                        var rawCACertificatePointer = allocator.allocate(ValueLayout.ADDRESS, rawCACertificate);
                        var x509CACert = d2i_X509(MemoryAddress.NULL, rawCACertificatePointer, rawCACertificate.byteSize());
                        if (MemoryAddress.NULL.equals(x509CACert)) {
                            logLastError(allocator, "openssl.errorLoadingCertificate");
                        } else if (SSL_CTX_add_client_CA(state.ctx, x509CACert) <= 0) {
                            logLastError(allocator, "openssl.errorAddingCertificate");
                        } else if (log.isDebugEnabled()) {
                            log.debug(sm.getString("openssl.addedClientCaCert", caCert.toString()));
                        }
                    }
                } else if (sslHostConfig.getCaCertificateFile() != null || sslHostConfig.getCaCertificatePath() != null) {
                    // Client certificate verification based on trusted CA files and dirs
                    //SSLContext.setCACertificate(state.ctx,
                    //        SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificateFile()),
                    //        SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificatePath()));
                    MemorySegment caCertificateFileNative = sslHostConfig.getCaCertificateFile() != null
                            ? allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificateFile())) : null;
                    MemorySegment caCertificatePathNative = sslHostConfig.getCaCertificatePath() != null
                            ? allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificatePath())) : null;
                    if (SSL_CTX_load_verify_locations(state.ctx,
                            caCertificateFileNative == null ? MemoryAddress.NULL : caCertificateFileNative,
                            caCertificatePathNative == null ? MemoryAddress.NULL : caCertificatePathNative) <= 0) {
                        logLastError(allocator, "openssl.errorConfiguringLocations");
                    } else {
                        var caCerts = SSL_CTX_get_client_CA_list(state.ctx);
                        if (MemoryAddress.NULL.equals(caCerts)) {
                            caCerts = SSL_load_client_CA_file(caCertificateFileNative);
                            if (!MemoryAddress.NULL.equals(caCerts)) {
                                SSL_CTX_set_client_CA_list(state.ctx, caCerts);
                            }
                        } else {
                            if (SSL_add_file_cert_subjects_to_stack(caCerts, caCertificateFileNative) <= 0) {
                                caCerts = MemoryAddress.NULL;
                            }
                        }
                        if (MemoryAddress.NULL.equals(caCerts)) {
                            log.warn(sm.getString("openssl.noCACerts"));
                        }
                    }
                }
            }

            if (negotiableProtocols != null && negotiableProtocols.size() > 0) {
                // int openSSLCallbackAlpnSelectProto(MemoryAddress ssl, MemoryAddress out, MemoryAddress outlen,
                //        MemoryAddress in, int inlen, MemoryAddress arg
                MethodHandle boundOpenSSLCallbackAlpnSelectProtoHandle = openSSLCallbackAlpnSelectProtoHandle.bindTo(this);
                NativeSymbol openSSLCallbackAlpnSelectProto = CLinker.systemCLinker().upcallStub(boundOpenSSLCallbackAlpnSelectProtoHandle,
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS
                                , ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), state.scope);
                SSL_CTX_set_alpn_select_cb(state.ctx, openSSLCallbackAlpnSelectProto, MemoryAddress.NULL);

                // Skip NPN (annoying and likely not useful anymore)
                //SSLContext.setNpnProtos(state.ctx, protocolsArray, SSL.SSL_SELECTOR_FAILURE_NO_ADVERTISE);
            }

            // Apply OpenSSLConfCmd if used
            OpenSSLConf openSslConf = sslHostConfig.getOpenSslConf();
            if (openSslConf != null && !MemoryAddress.NULL.equals(state.cctx)) {
                // Check OpenSSLConfCmd if used
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("openssl.checkConf"));
                }
                try {
                    if (!checkConf(openSslConf)) {
                        log.error(sm.getString("openssl.errCheckConf"));
                        throw new Exception(sm.getString("openssl.errCheckConf"));
                    }
                } catch (Exception e) {
                    throw new Exception(sm.getString("openssl.errCheckConf"), e);
                }
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("openssl.applyConf"));
                }
                try {
                    if (!applyConf(openSslConf)) {
                        log.error(sm.getString("openssl.errApplyConf"));
                        throw new SSLException(sm.getString("openssl.errApplyConf"));
                    }
                } catch (Exception e) {
                    throw new SSLException(sm.getString("openssl.errApplyConf"), e);
                }
                // Reconfigure the enabled protocols
                long opts = SSL_CTX_get_options(state.ctx);
                List<String> enabled = new ArrayList<>();
                // Seems like there is no way to explicitly disable SSLv2Hello
                // in OpenSSL so it is always enabled
                enabled.add(Constants.SSL_PROTO_SSLv2Hello);
                if ((opts & SSL_OP_NO_TLSv1()) == 0) {
                    enabled.add(Constants.SSL_PROTO_TLSv1);
                }
                if ((opts & SSL_OP_NO_TLSv1_1()) == 0) {
                    enabled.add(Constants.SSL_PROTO_TLSv1_1);
                }
                if ((opts & SSL_OP_NO_TLSv1_2()) == 0) {
                    enabled.add(Constants.SSL_PROTO_TLSv1_2);
                }
                if ((opts & SSL_OP_NO_TLSv1_3()) == 0) {
                    enabled.add(Constants.SSL_PROTO_TLSv1_3);
                }
                if ((opts & SSL_OP_NO_SSLv2()) == 0) {
                    enabled.add(Constants.SSL_PROTO_SSLv2);
                }
                if ((opts & SSL_OP_NO_SSLv3()) == 0) {
                    enabled.add(Constants.SSL_PROTO_SSLv3);
                }
                sslHostConfig.setEnabledProtocols(
                        enabled.toArray(new String[0]));
                // Reconfigure the enabled ciphers
                sslHostConfig.setEnabledCiphers(getCiphers(state.ctx));
            }

            sessionContext = new OpenSSLSessionContext(this);
            // If client authentication is being used, OpenSSL requires that
            // this is set so always set it in case an app is configured to
            // require it
            sessionContext.setSessionIdContext(DEFAULT_SESSION_ID_CONTEXT);
            sslHostConfig.setOpenSslContext(state.ctx.toRawLongValue());
            initialized = true;
        } catch (Exception e) {
            log.warn(sm.getString("openssl.errorSSLCtxInit"), e);
            destroy();
        }
    }


    public MemoryAddress getSSLContext() {
        return state.ctx;
    }

    // DH *(*tmp_dh_callback)(SSL *ssl, int is_export, int keylength)
    public long/*MemoryAddress*/ openSSLCallbackTmpDH(MemoryAddress ssl, int isExport, int keylength) {
        var pkey = SSL_get_privatekey(ssl);
        int type = (MemoryAddress.NULL.equals(pkey)) ? EVP_PKEY_NONE() : EVP_PKEY_base_id(pkey);
        /*
         * OpenSSL will call us with either keylen == 512 or keylen == 1024
         * (see the definition of SSL_EXPORT_PKEYLENGTH in ssl_locl.h).
         * Adjust the DH parameter length according to the size of the
         * RSA/DSA private key used for the current connection, and always
         * use at least 1024-bit parameters.
         * Note: This may cause interoperability issues with implementations
         * which limit their DH support to 1024 bit - e.g. Java 7 and earlier.
         * In this case, SSLCertificateFile can be used to specify fixed
         * 1024-bit DH parameters (with the effect that OpenSSL skips this
         * callback).
         */
        int keylen = 0;
        if ((type == EVP_PKEY_RSA()) || (type == EVP_PKEY_DSA())) {
            keylen = EVP_PKEY_bits(pkey);
        }
        for (int i = 0; i < dhParameters.length; i++) {
            if (keylen >= dhParameters[i].min) {
                return dhParameters[i].dh.toRawLongValue();
            }
        }
        return MemoryAddress.NULL.toRawLongValue();
    }

    // int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
    //        const unsigned char *in, unsigned int inlen, void *arg)
    public int openSSLCallbackAlpnSelectProto(MemoryAddress ssl, MemoryAddress out, MemoryAddress outlen,
            MemoryAddress in, int inlen, MemoryAddress arg) {
        // No scope, so byte by byte read, the ALPN data is small
        byte[] advertisedBytes = new byte[inlen];
        for (int i = 0; i < inlen; i++) {
            advertisedBytes[i] = in.get(ValueLayout.JAVA_BYTE, i);
        }
        ArrayList<byte[]> negotiableProtocolsBytes = new ArrayList<>(negotiableProtocols.size() + 1);
        for (String negotiableProtocol : negotiableProtocols) {
            negotiableProtocolsBytes.add(negotiableProtocol.getBytes());
        }
        negotiableProtocolsBytes.add(HTTP_11_PROTOCOL);
        for (byte[] negotiableProtocolBytes : negotiableProtocolsBytes) {
            for (int i = 0; i <= advertisedBytes.length - negotiableProtocolBytes.length; i++) {
                if (advertisedBytes[i] == negotiableProtocolBytes[0]) {
                    for (int j = 0; j < negotiableProtocolBytes.length; j++) {
                        if (advertisedBytes[i + j] == negotiableProtocolBytes[j]) {
                            if (j == negotiableProtocolBytes.length - 1) {
                                // Match
                                out.set(ValueLayout.ADDRESS, 0, in.addOffset(i));
                                outlen.set(ValueLayout.JAVA_BYTE, 0, (byte) negotiableProtocolBytes.length);
                                return SSL_TLSEXT_ERR_OK();
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        return SSL_TLSEXT_ERR_NOACK();
    }

    public int openSSLCallbackVerify(int preverify_ok, MemoryAddress /*X509_STORE_CTX*/ x509ctx) {
        if (log.isDebugEnabled()) {
            log.debug("Verification with mode [" + certificateVerifyMode + "]");
        }
        MemoryAddress ssl = X509_STORE_CTX_get_ex_data(x509ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        int ok = preverify_ok;
        int errnum = X509_STORE_CTX_get_error(x509ctx);
        int errdepth = X509_STORE_CTX_get_error_depth(x509ctx);
        if (certificateVerifyMode == -1 /*SSL_CVERIFY_UNSET*/
                || certificateVerifyMode == SSL_VERIFY_NONE()) {
            return 1;
        }
        /*SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) -> ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) \
        || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) \
        || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) \
        || (errnum == X509_V_ERR_CERT_UNTRUSTED) \
        || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))*/
        boolean verifyErrorIsOptional = (errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT())
                || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN())
                || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY())
                || (errnum == X509_V_ERR_CERT_UNTRUSTED())
                || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE());
        if (verifyErrorIsOptional && (certificateVerifyMode == OPTIONAL_NO_CA)) {
            ok = 1;
            SSL_set_verify_result(ssl, X509_V_OK());
        }
        /*
         * Expired certificates vs. "expired" CRLs: by default, OpenSSL
         * turns X509_V_ERR_CRL_HAS_EXPIRED into a "certificate_expired(45)"
         * SSL alert, but that's not really the message we should convey to the
         * peer (at the very least, it's confusing, and in many cases, it's also
         * inaccurate, as the certificate itself may very well not have expired
         * yet). We set the X509_STORE_CTX error to something which OpenSSL's
         * s3_both.c:ssl_verify_alarm_type() maps to SSL_AD_CERTIFICATE_UNKNOWN,
         * i.e. the peer will receive a "certificate_unknown(46)" alert.
         * We do not touch errnum, though, so that later on we will still log
         * the "real" error, as returned by OpenSSL.
         */
        if (ok == 0 && errnum == X509_V_ERR_CRL_HAS_EXPIRED()) {
            X509_STORE_CTX_set_error(x509ctx, -1);
        }

        // OCSP
        if (!noOcspCheck && (ok > 0)) {
            /* If there was an optional verification error, it's not
             * possible to perform OCSP validation since the issuer may be
             * missing/untrusted.  Fail in that case.
             */
            if (verifyErrorIsOptional) {
                X509_STORE_CTX_set_error(x509ctx, X509_V_ERR_APPLICATION_VERIFICATION());
                errnum = X509_V_ERR_APPLICATION_VERIFICATION();
                ok = 0;
            } else {
                int ocspResponse = OCSP_STATUS_UNKNOWN;
                // ocspResponse = ssl_verify_OCSP(x509_ctx);
                MemoryAddress x509 = X509_STORE_CTX_get_current_cert(x509ctx);
                if (!MemoryAddress.NULL.equals(x509)) {
                    // No need to check cert->valid, because ssl_verify_OCSP() only
                    // is called if OpenSSL already successfully verified the certificate
                    // (parameter "ok" in SSL_callback_SSL_verify() must be true).
                    if (X509_check_issued(x509, x509) == X509_V_OK()) {
                        // don't do OCSP checking for valid self-issued certs
                        X509_STORE_CTX_set_error(x509ctx, X509_V_OK());
                    } else {
                        /* if we can't get the issuer, we cannot perform OCSP verification */
                        MemoryAddress issuer = X509_STORE_CTX_get0_current_issuer(x509ctx);
                        if (!MemoryAddress.NULL.equals(issuer)) {
                            //ssl_ocsp_request(x509, issuer, x509ctx);
                            int nid = X509_get_ext_by_NID(x509, NID_info_access(), -1);
                            if (nid >= 0) {
                                try (var scope = ResourceScope.newConfinedScope()) {
                                    MemoryAddress ext = X509_get_ext(x509, nid);
                                    MemoryAddress os = X509_EXTENSION_get_data(ext);
                                    int len = ASN1_STRING_length(os);
                                    MemoryAddress data = ASN1_STRING_get0_data(os);
                                    // ocsp_urls = decode_OCSP_url(os);
                                    byte[] asn1String = new byte[len + 1];
                                    for (int i = 0; i < len; i++) {
                                        asn1String[i] = data.get(ValueLayout.JAVA_BYTE, i);
                                    }
                                    asn1String[len] = 0;
                                    Asn1Parser parser = new Asn1Parser(asn1String);
                                    // Parse the byte sequence
                                    ArrayList<String> urls = new ArrayList<>();
                                    try {
                                        parseOCSPURLs(parser, urls);
                                    } catch (Exception e) {
                                        log.error("OCSP error", e);
                                    }
                                    if (!urls.isEmpty()) {
                                        // FIXME: OCSP requests and response from sslutils.c ssl_ocsp_request
                                    }
                                }
                            }
                        }
                    }
                }
                if (ocspResponse == OCSP_STATUS_REVOKED) {
                    ok = 0;
                    errnum = X509_STORE_CTX_get_error(x509ctx);
                } else if (ocspResponse == OCSP_STATUS_UNKNOWN) {
                    errnum = X509_STORE_CTX_get_error(x509ctx);
                    if (errnum <= 0) {
                        ok = 0;
                    }
                }
            }
        }

        if (errdepth > sslHostConfig.getCertificateVerificationDepth()) {
            // Certificate Verification: Certificate Chain too long
            ok = 0;
        }
        return ok;
    }


    private static final int ASN1_SEQUENCE = 0x30;
    private static final int ASN1_OID      = 0x06;
    private static final int ASN1_STRING   = 0x86;
    private static final byte[] OCSP_OID = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01};

    private boolean parseOCSPURLs(Asn1Parser parser, ArrayList<String> urls) {
        while (true) {
            int tag = parser.peekTag();
            if (tag == ASN1_SEQUENCE) {
                parser.parseTag(ASN1_SEQUENCE);
                parser.parseFullLength();
            } else if (tag == ASN1_OID) {
                parser.parseTag(ASN1_OID);
                int oidLen = parser.parseLength();
                byte[] oid = new byte[oidLen];
                parser.parseBytes(oid);
                if (Arrays.compareUnsigned(oid, 0, OCSP_OID.length, OCSP_OID, 0, OCSP_OID.length) == 0) {
                    Asn1Parser newParser = new Asn1Parser(Arrays.copyOfRange(oid, 8, oid.length));
                    newParser.parseTag(ASN1_STRING);
                    int urlLen = newParser.parseLength();
                    byte[] url = new byte[urlLen];
                    urls.add(new String(url));
                }
            } else if (tag == 0) {
                // Reached the end
                return true;
            } else {
                break;
            }
        }
        return false;
    }


    public int openSSLCallbackCertVerify(MemoryAddress /*X509_STORE_CTX*/ x509_ctx, MemoryAddress param) {
        if (log.isDebugEnabled()) {
            log.debug("Certificate verification");
        }
        MemoryAddress ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        MemoryAddress /*STACK_OF(X509)*/ sk = X509_STORE_CTX_get0_untrusted(x509_ctx);
        int len = OPENSSL_sk_num(sk);
        byte[][] certificateChain = new byte[len][];
        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            for (int i = 0; i < len; i++) {
                MemoryAddress/*(X509*)*/ x509 = OPENSSL_sk_value(sk, i);
                MemorySegment bufPointer = allocator.allocate(ValueLayout.ADDRESS, MemoryAddress.NULL);
                int length = i2d_X509(x509, bufPointer);
                if (length < 0) {
                    certificateChain[i] = new byte[0];
                    continue;
                }
                MemoryAddress buf = bufPointer.get(ValueLayout.ADDRESS, 0);
                certificateChain[i] = MemorySegment.ofAddressNative(buf, length, scope).toArray(ValueLayout.JAVA_BYTE);
                CRYPTO_free(buf, OPENSSL_FILE(), OPENSSL_LINE()); // OPENSSL_free macro
            }
            MemoryAddress cipher = SSL_get_current_cipher(ssl);
            String authMethod = (MemoryAddress.NULL.equals(cipher)) ? "UNKNOWN"
                    : getCipherAuthenticationMethod(SSL_CIPHER_get_auth_nid(cipher), SSL_CIPHER_get_kx_nid(cipher));
            X509Certificate[] peerCerts = certificates(certificateChain);
            try {
                x509TrustManager.checkClientTrusted(peerCerts, authMethod);
                return 1;
            } catch (Exception e) {
                log.debug(sm.getString("openssl.certificateVerificationFailed"), e);
            }
        }
        return 0;
    }

    private static final int NID_kx_rsa = 1037/*NID_kx_rsa()*/;
    //private static final int NID_kx_dhe = NID_kx_dhe();
    //private static final int NID_kx_ecdhe = NID_kx_ecdhe();

    //private static final int NID_auth_rsa = NID_auth_rsa();
    //private static final int NID_auth_dss = NID_auth_dss();
    //private static final int NID_auth_null = NID_auth_null();
    //private static final int NID_auth_ecdsa = NID_auth_ecdsa();

    //private static final int SSL_kRSA = 1;
    private static final int SSL_kDHr = 2;
    private static final int SSL_kDHd = 4;
    private static final int SSL_kEDH = 8;
    private static final int SSL_kDHE = SSL_kEDH;
    private static final int SSL_kKRB5 = 10;
    private static final int SSL_kECDHr = 20;
    private static final int SSL_kECDHe = 40;
    private static final int SSL_kEECDH = 80;
    private static final int SSL_kECDHE = SSL_kEECDH;
    //private static final int SSL_kPSK = 100;
    //private static final int SSL_kGOST = 200;
    //private static final int SSL_kSRP = 400;

    private static final int SSL_aRSA = 1;
    private static final int SSL_aDSS = 2;
    private static final int SSL_aNULL = 4;
    //private static final int SSL_aDH = 8;
    //private static final int SSL_aECDH = 10;
    //private static final int SSL_aKRB5 = 20;
    private static final int SSL_aECDSA = 40;
    //private static final int SSL_aPSK = 80;
    //private static final int SSL_aGOST94 = 100;
    //private static final int SSL_aGOST01 = 200;
    //private static final int SSL_aSRP = 400;

    private static final String SSL_TXT_RSA = SSL_TXT_RSA().getUtf8String(0);
    private static final String SSL_TXT_DH = SSL_TXT_DH().getUtf8String(0);
    private static final String SSL_TXT_DSS = SSL_TXT_DSS().getUtf8String(0);
    private static final String SSL_TXT_KRB5 = "KRB5";
    private static final String SSL_TXT_ECDH = SSL_TXT_ECDH().getUtf8String(0);
    private static final String SSL_TXT_ECDSA = SSL_TXT_ECDSA().getUtf8String(0);

    private static String getCipherAuthenticationMethod(int auth, int kx) {
        switch (kx) {
        case NID_kx_rsa:
            return SSL_TXT_RSA;
        case SSL_kDHr:
            return SSL_TXT_DH + "_" + SSL_TXT_RSA;
        case SSL_kDHd:
            return SSL_TXT_DH + "_" + SSL_TXT_DSS;
        case SSL_kDHE:
            switch (auth) {
            case SSL_aDSS:
                return "DHE_" + SSL_TXT_DSS;
            case SSL_aRSA:
                return "DHE_" + SSL_TXT_RSA;
            case SSL_aNULL:
                return SSL_TXT_DH + "_anon";
            default:
                return "UNKNOWN";
            }
        case SSL_kKRB5:
            return SSL_TXT_KRB5;
        case SSL_kECDHr:
            return SSL_TXT_ECDH + "_" + SSL_TXT_RSA;
        case SSL_kECDHe:
            return SSL_TXT_ECDH + "_" + SSL_TXT_ECDSA;
        case SSL_kECDHE:
            switch (auth) {
            case SSL_aECDSA:
                return "ECDHE_" + SSL_TXT_ECDSA;
            case SSL_aRSA:
                return "ECDHE_" + SSL_TXT_RSA;
            case SSL_aNULL:
                return SSL_TXT_ECDH + "_anon";
            default:
                return "UNKNOWN";
            }
        default:
            return "UNKNOWN";
        }
    }

    private String callbackPassword = null;

    public int openSSLCallbackPassword(MemoryAddress /*char **/ buf, int bufsiz, int verify, MemoryAddress /*void **/ cb) {
        if (log.isDebugEnabled()) {
            log.debug("Return password for certificate");
        }
        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            MemorySegment callbackPasswordNative = allocator.allocateUtf8String(callbackPassword);
            if (callbackPasswordNative.byteSize() > bufsiz) {
                // The password is too long
                log.error(sm.getString("openssl.passwordTooLong"));
            } else {
                MemorySegment bufSegment = MemorySegment.ofAddressNative(buf, bufsiz, scope);
                bufSegment.copyFrom(callbackPasswordNative);
                return (int) callbackPasswordNative.byteSize();
            }
        }        
        return 0;
    }


    public void addCertificate(SSLHostConfigCertificate certificate) throws Exception {
        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            int index = getCertificateIndex(certificate);
            // Load Server key and certificate
            if (certificate.getCertificateFile() != null) {
                // Set certificate
                // Make the password available for the callback
                callbackPassword = certificate.getCertificateKeyPassword();
                //SSLContext.setCertificate(state.ctx,
                //        SSLHostConfig.adjustRelativePath(certificate.getCertificateFile()),
                //        SSLHostConfig.adjustRelativePath(certificate.getCertificateKeyFile()),
                //        certificate.getCertificateKeyPassword(), getCertificateIndex(certificate));
                var certificateFileNative = allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(certificate.getCertificateFile()));
                var certificateKeyFileNative = (certificate.getCertificateKeyFile() == null) ? certificateFileNative
                        : allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(certificate.getCertificateKeyFile()));
                MemoryAddress bio;
                MemoryAddress cert = MemoryAddress.NULL;
                MemoryAddress key = MemoryAddress.NULL;
                if (certificate.getCertificateFile().endsWith(".pkcs12")) {
                    // Load pkcs12
                    bio = BIO_new(BIO_s_file());
                    //#  define BIO_read_filename(b,name)
                    //        (int)BIO_ctrl(b,BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_READ,(char *)(name))
                    if (BIO_ctrl(bio, BIO_C_SET_FILENAME(), BIO_CLOSE() | BIO_FP_READ(), certificateFileNative) <= 0) {
                        BIO_free(bio);
                        log.error(sm.getString("openssl.errorLoadingCertificate", "[0]:" + certificate.getCertificateFile()));
                        return;
                    }
                    MemoryAddress p12 = d2i_PKCS12_bio(bio, MemoryAddress.NULL);
                    BIO_free(bio);
                    if (MemoryAddress.NULL.equals(p12)) {
                        log.error(sm.getString("openssl.errorLoadingCertificate", "[1]:" + certificate.getCertificateFile()));
                        return;
                    }
                    MemoryAddress passwordAddress = MemoryAddress.NULL;
                    int passwordLength = 0;
                    if (callbackPassword != null && callbackPassword.length() > 0) {
                        MemorySegment password = allocator.allocateUtf8String(callbackPassword);
                        passwordAddress = password.address();
                        passwordLength = (int) (password.byteSize() - 1);
                    }
                    if (PKCS12_verify_mac(p12, passwordAddress, passwordLength) <= 0) {
                        // Bad password
                        log.error(sm.getString("openssl.errorLoadingCertificate", "[2]:" + certificate.getCertificateFile()));
                        PKCS12_free(p12);
                        return;
                    }
                    MemorySegment certPointer = allocator.allocate(ValueLayout.ADDRESS);
                    MemorySegment keyPointer = allocator.allocate(ValueLayout.ADDRESS);
                    if (PKCS12_parse(p12, passwordAddress, keyPointer, certPointer, MemoryAddress.NULL) <= 0) {
                        log.error(sm.getString("openssl.errorLoadingCertificate", "[3]:" + certificate.getCertificateFile()));
                        PKCS12_free(p12);
                        return;
                    }
                    PKCS12_free(p12);
                    cert = certPointer.get(ValueLayout.ADDRESS, 0);
                    key = keyPointer.get(ValueLayout.ADDRESS, 0);
                } else {
                    // Load key
                    bio = BIO_new(BIO_s_file());
                    //#  define BIO_read_filename(b,name)
                    //        (int)BIO_ctrl(b,BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_READ,(char *)(name))
                    if (BIO_ctrl(bio, BIO_C_SET_FILENAME(), BIO_CLOSE() | BIO_FP_READ(), certificateKeyFileNative) <= 0) {
                        BIO_free(bio);
                        log.error(sm.getString("openssl.errorLoadingCertificate", certificate.getCertificateKeyFile()));
                        return;
                    }
                    key = MemoryAddress.NULL;
                    for (int i = 0; i < 3; i++) {
                        key = PEM_read_bio_PrivateKey(bio, MemoryAddress.NULL, state.openSSLCallbackPassword, MemoryAddress.NULL);
                        if (!MemoryAddress.NULL.equals(key)) {
                            break;
                        }
                        BIO_ctrl(bio, BIO_CTRL_RESET(), 0, MemoryAddress.NULL);
                    }
                    BIO_free(bio);
                    if (MemoryAddress.NULL.equals(key)) {
                        if (!MemoryAddress.NULL.equals(OpenSSLLifecycleListener.enginePointer)) {
                            key = ENGINE_load_private_key(OpenSSLLifecycleListener.enginePointer, certificateKeyFileNative,
                                    MemoryAddress.NULL, MemoryAddress.NULL);
                        }
                    }
                    if (MemoryAddress.NULL.equals(key)) {
                        log.error(sm.getString("openssl.errorLoadingCertificate", certificate.getCertificateKeyFile()));
                        return;
                    }
                    // Load certificate
                    bio = BIO_new(BIO_s_file());
                    if (BIO_ctrl(bio, BIO_C_SET_FILENAME(), BIO_CLOSE() | BIO_FP_READ(), certificateFileNative) <= 0) {
                        BIO_free(bio);
                        log.error(sm.getString("openssl.errorLoadingCertificate", certificate.getCertificateFile()));
                        return;
                    }
                    cert = PEM_read_bio_X509_AUX(bio, MemoryAddress.NULL, state.openSSLCallbackPassword,
                            MemoryAddress.NULL);
                    if (MemoryAddress.NULL.equals(cert) &&
                            // FIXME: Unfortunately jextract doesn't convert this ERR_GET_REASON(ERR_peek_last_error())
                            ((ERR_peek_last_error() & 0X7FFFFF) == PEM_R_NO_START_LINE())) {
                        ERR_clear_error();
                        BIO_ctrl(bio, BIO_CTRL_RESET(), 0, MemoryAddress.NULL);
                        cert = d2i_X509_bio(bio, MemoryAddress.NULL);
                    }
                    BIO_free(bio);
                    if (MemoryAddress.NULL.equals(cert)) {
                        log.error(sm.getString("openssl.errorLoadingCertificate", certificate.getCertificateFile()));
                        return;
                    }
                }
                if (SSL_CTX_use_certificate(state.ctx, cert) <= 0) {
                    logLastError(allocator, "openssl.errorLoadingCertificate");
                    return;
                }
                if (SSL_CTX_use_PrivateKey(state.ctx, key) <= 0) {
                    logLastError(allocator, "openssl.errorLoadingPrivateKey");
                    return;
                }
                if (SSL_CTX_check_private_key(state.ctx) <= 0) {
                    logLastError(allocator, "openssl.errorPrivateKeyCheck");
                    return;
                }
                // Try to read DH parameters from the (first) SSLCertificateFile
                if (index == SSL_AIDX_RSA) {
                    bio = BIO_new_file(certificateFileNative, allocator.allocateUtf8String("r"));
                    var dh = PEM_read_bio_DHparams(bio, MemoryAddress.NULL, MemoryAddress.NULL, MemoryAddress.NULL);
                    BIO_free(bio);
                    // #  define SSL_CTX_set_tmp_dh(ctx,dh) \
                    //           SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)(dh))
                    if (!MemoryAddress.NULL.equals(dh)) {
                        SSL_CTX_ctrl(state.ctx, SSL_CTRL_SET_TMP_DH(), 0, dh);
                        DH_free(dh);
                    }
                }
                // Similarly, try to read the ECDH curve name from SSLCertificateFile...
                bio = BIO_new_file(certificateFileNative, allocator.allocateUtf8String("r"));
                var ecparams = PEM_read_bio_ECPKParameters(bio, MemoryAddress.NULL, MemoryAddress.NULL, MemoryAddress.NULL);
                BIO_free(bio);
                if (!MemoryAddress.NULL.equals(ecparams)) {
                    int nid = EC_GROUP_get_curve_name(ecparams);
                    var eckey = EC_KEY_new_by_curve_name(nid);
                    // #  define SSL_CTX_set_tmp_ecdh(ctx,ecdh) \
                    //           SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))
                    SSL_CTX_ctrl(state.ctx, SSL_CTRL_SET_TMP_ECDH(), 0, eckey);
                    EC_KEY_free(eckey);
                    EC_GROUP_free(ecparams);
                }
                // Set callback for DH parameters
                MethodHandle boundOpenSSLCallbackTmpDHHandle = openSSLCallbackTmpDHHandle.bindTo(this);
                NativeSymbol openSSLCallbackTmpDH = CLinker.systemCLinker().upcallStub(boundOpenSSLCallbackTmpDHHandle,
                        FunctionDescriptor.of(ValueLayout.JAVA_LONG/*ValueLayout.ADDRESS*/, ValueLayout.ADDRESS,
                                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), state.scope);
                SSL_CTX_set_tmp_dh_callback(state.ctx, openSSLCallbackTmpDH);
                callbackPassword = null;
                // Set certificate chain file
                if (certificate.getCertificateChainFile() != null) {
                    var certificateChainFileNative =
                            allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(certificate.getCertificateChainFile()));
                    // SSLContext.setCertificateChainFile(state.ctx,
                    //        SSLHostConfig.adjustRelativePath(certificate.getCertificateChainFile()), false);
                    if (SSL_CTX_use_certificate_chain_file(state.ctx, certificateChainFileNative) <= 0) {
                        log.error(sm.getString("openssl.errorLoadingCertificate", certificate.getCertificateChainFile()));
                    }
                }
                // Set revocation
                //SSLContext.setCARevocation(state.ctx,
                //        SSLHostConfig.adjustRelativePath(
                //                sslHostConfig.getCertificateRevocationListFile()),
                //        SSLHostConfig.adjustRelativePath(
                //                sslHostConfig.getCertificateRevocationListPath()));
                MemoryAddress certificateStore = (state.ctx);
                if (sslHostConfig.getCertificateRevocationListFile() != null) {
                    MemoryAddress x509Lookup = X509_STORE_add_lookup(certificateStore, X509_LOOKUP_file());
                    var certificateRevocationListFileNative =
                            allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(sslHostConfig.getCertificateRevocationListFile()));
                    //X509_LOOKUP_ctrl(lookup,X509_L_FILE_LOAD,file,type,NULL)
                    if (X509_LOOKUP_ctrl(x509Lookup, X509_L_FILE_LOAD(), certificateRevocationListFileNative,
                            X509_FILETYPE_PEM(), MemoryAddress.NULL) <= 0) {
                        log.error(sm.getString("openssl.errorLoadingCertificateRevocationList", sslHostConfig.getCertificateRevocationListFile()));
                    }
                }
                if (sslHostConfig.getCertificateRevocationListPath() != null) {
                    MemoryAddress x509Lookup = X509_STORE_add_lookup(certificateStore, X509_LOOKUP_hash_dir());
                    var certificateRevocationListPathNative =
                            allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(sslHostConfig.getCertificateRevocationListPath()));
                    //X509_LOOKUP_ctrl(lookup,X509_L_ADD_DIR,path,type,NULL)
                    if (X509_LOOKUP_ctrl(x509Lookup, X509_L_ADD_DIR(), certificateRevocationListPathNative,
                            X509_FILETYPE_PEM(), MemoryAddress.NULL) <= 0) {
                        log.error(sm.getString("openssl.errorLoadingCertificateRevocationList", sslHostConfig.getCertificateRevocationListPath()));
                    }
                }
                X509_STORE_set_flags(certificateStore, X509_V_FLAG_CRL_CHECK() | X509_V_FLAG_CRL_CHECK_ALL());
            } else {
                String alias = certificate.getCertificateKeyAlias();
                X509KeyManager x509KeyManager = certificate.getCertificateKeyManager();
                if (alias == null) {
                    alias = "tomcat";
                }
                X509Certificate[] chain = x509KeyManager.getCertificateChain(alias);
                if (chain == null) {
                    alias = findAlias(x509KeyManager, certificate);
                    chain = x509KeyManager.getCertificateChain(alias);
                }
                PrivateKey key = x509KeyManager.getPrivateKey(alias);
                StringBuilder sb = new StringBuilder(BEGIN_KEY);
                sb.append(Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded()));
                sb.append(END_KEY);
                //SSLContext.setCertificateRaw(state.ctx, chain[0].getEncoded(),
                //        sb.toString().getBytes(StandardCharsets.US_ASCII),
                //        getCertificateIndex(certificate));
                var rawCertificate = allocator.allocateArray(ValueLayout.JAVA_BYTE, chain[0].getEncoded());
                var rawCertificatePointer = allocator.allocate(ValueLayout.ADDRESS, rawCertificate);
                var rawKey = allocator.allocateArray(ValueLayout.JAVA_BYTE, sb.toString().getBytes(StandardCharsets.US_ASCII));
                var x509cert = d2i_X509(MemoryAddress.NULL, rawCertificatePointer, rawCertificate.byteSize());
                if (MemoryAddress.NULL.equals(x509cert)) {
                    logLastError(allocator, "openssl.errorLoadingCertificate");
                    return;
                }
                var bio = BIO_new(BIO_s_mem());
                BIO_write(bio, rawKey.address(), (int) rawKey.byteSize());
                MemoryAddress privateKeyAddress = PEM_read_bio_PrivateKey(bio, MemoryAddress.NULL, MemoryAddress.NULL, MemoryAddress.NULL);
                BIO_free(bio);
                if (MemoryAddress.NULL.equals(privateKeyAddress)) {
                    logLastError(allocator, "openssl.errorLoadingPrivateKey");
                    return;
                }
                if (SSL_CTX_use_certificate(state.ctx, x509cert) <= 0) {
                    logLastError(allocator, "openssl.errorLoadingCertificate");
                    return;
                }
                if (SSL_CTX_use_PrivateKey(state.ctx, privateKeyAddress) <= 0) {
                    logLastError(allocator, "openssl.errorLoadingPrivateKey");
                    return;
                }
                if (SSL_CTX_check_private_key(state.ctx) <= 0) {
                    logLastError(allocator, "openssl.errorPrivateKeyCheck");
                    return;
                }
                // Set callback for DH parameters
                MethodHandle boundOpenSSLCallbackTmpDHHandle = openSSLCallbackTmpDHHandle.bindTo(this);
                NativeSymbol openSSLCallbackTmpDH = CLinker.systemCLinker().upcallStub(boundOpenSSLCallbackTmpDHHandle,
                        FunctionDescriptor.of(ValueLayout.JAVA_LONG/*ValueLayout.ADDRESS*/, ValueLayout.ADDRESS,
                                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), state.scope);
                SSL_CTX_set_tmp_dh_callback(state.ctx, openSSLCallbackTmpDH);
                for (int i = 1; i < chain.length; i++) {
                    //SSLContext.addChainCertificateRaw(state.ctx, chain[i].getEncoded());
                    var rawCertificateChain = allocator.allocateArray(ValueLayout.JAVA_BYTE, chain[i].getEncoded());
                    var rawCertificateChainPointer = allocator.allocate(ValueLayout.ADDRESS, rawCertificateChain);
                    var x509certChain = d2i_X509(MemoryAddress.NULL, rawCertificateChainPointer, rawCertificateChain.byteSize());
                    if (MemoryAddress.NULL.equals(x509certChain)) {
                        logLastError(allocator, "openssl.errorLoadingCertificate");
                        return;
                    }
                    // # define SSL_CTX_add0_chain_cert(ctx,x509) SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)(x509))
                    if (SSL_CTX_ctrl(state.ctx, SSL_CTRL_CHAIN_CERT(), 0, x509certChain) <= 0) {
                        logLastError(allocator, "openssl.errorAddingCertificate");
                        return;
                    }
                }
            }
        }
    }


    private static int getCertificateIndex(SSLHostConfigCertificate certificate) {
        int result = -1;
        // If the type is undefined there will only be one certificate (enforced
        // in SSLHostConfig) so use the RSA slot.
        if (certificate.getType() == Type.RSA || certificate.getType() == Type.UNDEFINED) {
            result = SSL_AIDX_RSA;
        } else if (certificate.getType() == Type.EC) {
            result = SSL_AIDX_ECC;
        } else if (certificate.getType() == Type.DSA) {
            result = SSL_AIDX_DSA;
        } else {
            result = SSL_AIDX_MAX;
        }
        return result;
    }


    /*
     * Find a valid alias when none was specified in the config.
     */
    private static String findAlias(X509KeyManager keyManager,
            SSLHostConfigCertificate certificate) {

        Type type = certificate.getType();
        String result = null;

        List<Type> candidateTypes = new ArrayList<>();
        if (Type.UNDEFINED.equals(type)) {
            // Try all types to find an suitable alias
            candidateTypes.addAll(Arrays.asList(Type.values()));
            candidateTypes.remove(Type.UNDEFINED);
        } else {
            // Look for the specific type to find a suitable alias
            candidateTypes.add(type);
        }

        Iterator<Type> iter = candidateTypes.iterator();
        while (result == null && iter.hasNext()) {
            result = keyManager.chooseServerAlias(iter.next().toString(),  null,  null);
        }

        return result;
    }

    private static X509TrustManager chooseTrustManager(TrustManager[] managers) {
        for (TrustManager m : managers) {
            if (m instanceof X509TrustManager) {
                return (X509TrustManager) m;
            }
        }
        throw new IllegalStateException(sm.getString("openssl.trustManagerMissing"));
    }

    private static X509Certificate[] certificates(byte[][] chain) {
        X509Certificate[] peerCerts = new X509Certificate[chain.length];
        for (int i = 0; i < peerCerts.length; i++) {
            peerCerts[i] = new OpenSSLX509Certificate(chain[i]);
        }
        return peerCerts;
    }


    private static void logLastError(SegmentAllocator allocator, String string) {
        var buf = allocator.allocateArray(ValueLayout.JAVA_BYTE, new byte[128]);
        ERR_error_string(ERR_get_error(), buf);
        String err = buf.getUtf8String(0);
        log.error(sm.getString(string, err));
    }


    @Override
    public SSLSessionContext getServerSessionContext() {
        return sessionContext;
    }

    @Override
    public SSLEngine createSSLEngine() {
        return new OpenSSLEngine(cleaner, state.ctx, defaultProtocol, false, sessionContext,
                (negotiableProtocols != null && negotiableProtocols.size() > 0), initialized,
                sslHostConfig.getCertificateVerificationDepth(),
                sslHostConfig.getCertificateVerification() == CertificateVerification.OPTIONAL_NO_CA);
    }

    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        throw new UnsupportedOperationException();
    }

    @Override
    public SSLParameters getSupportedSSLParameters() {
        throw new UnsupportedOperationException();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] chain = null;
        X509KeyManager x509KeyManager = certificate.getCertificateKeyManager();
        if (x509KeyManager != null) {
            if (alias == null) {
                alias = "tomcat";
            }
            chain = x509KeyManager.getCertificateChain(alias);
            if (chain == null) {
                alias = findAlias(x509KeyManager, certificate);
                chain = x509KeyManager.getCertificateChain(alias);
            }
        }

        return chain;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] acceptedCerts = null;
        if (x509TrustManager != null) {
            acceptedCerts = x509TrustManager.getAcceptedIssuers();
        }
        return acceptedCerts;
    }


    private static class OpenSSLState implements Runnable {

        final ResourceScope scope;
        // SSL context
        final MemoryAddress ctx;
        // OpenSSLConfCmd context
        final MemoryAddress cctx;
        // Password callback
        final NativeSymbol openSSLCallbackPassword;

        private OpenSSLState(ResourceScope scope, MemoryAddress cctx, MemoryAddress ctx,
                NativeSymbol openSSLCallbackPassword) {
            this.scope = scope;
            this.cctx = cctx;
            this.ctx = ctx;
            this.openSSLCallbackPassword = openSSLCallbackPassword;
        }

        @Override
        public void run() {
            try {
                SSL_CTX_free(ctx);
                if (!MemoryAddress.NULL.equals(cctx)) {
                    SSL_CONF_CTX_free(cctx);
                }
            } finally {
                scope.close();
            }
        }
    }
}
