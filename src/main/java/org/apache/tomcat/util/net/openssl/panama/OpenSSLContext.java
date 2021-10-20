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

import jdk.incubator.foreign.Addressable;
import jdk.incubator.foreign.CLinker;
import jdk.incubator.foreign.FunctionDescriptor;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.NativeSymbol;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SegmentAllocator;
import jdk.incubator.foreign.ValueLayout;

import static org.apache.tomcat.util.openssl.openssl_h.*;

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
import org.apache.tomcat.jni.CertificateVerifier;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.jni.SSLConf;
import org.apache.tomcat.jni.SSLContext;
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

    private static final StringManager sm = StringManager.getManager(OpenSSLContext.class);

    private static final String defaultProtocol = "TLS";

    private static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----\n";
    private static final Object END_KEY = "\n-----END PRIVATE KEY-----";

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

    private static final Cleaner cleaner = Cleaner.create();

    private final SSLHostConfig sslHostConfig;
    private final SSLHostConfigCertificate certificate;
    private final List<String> negotiableProtocols;
    private String[] negotiableProtocolsArray;

    private int certificateVerifyMode = -1;

    private OpenSSLSessionContext sessionContext;
    private X509TrustManager x509TrustManager;
    private String enabledProtocol;
    private boolean initialized = false;

    private final OpenSSLState state;
    private final Cleanable cleanable;

    private static String[] getCiphers(MemoryAddress sslCtx) {
        MemoryAddress sk = SSL_CTX_get_ciphers(sslCtx);
        int len = sk_SSL_CIPHER_num(sk);
        if (len <= 0) {
            return null;
        }
        ArrayList<String> ciphers = new ArrayList<>(len);
        for (int i = 0; i < len; i++) {
            MemoryAddress cipher = sk_SSL_CIPHER_value(sk, i);
            MemoryAddress cipherName = SSL_CIPHER_get_name(cipher);
            ciphers.add(cipherName.getUtf8String(0));
        }
        return ciphers.toArray(new String[0]);
    }

    public OpenSSLContext(SSLHostConfigCertificate certificate, List<String> negotiableProtocols)
            throws SSLException {
        this.sslHostConfig = certificate.getSSLHostConfig();
        this.certificate = certificate;
        ResourceScope scope = ResourceScope.newSharedScope();
        
        MemoryAddress ctx = MemoryAddress.NULL;
        MemoryAddress cctx = MemoryAddress.NULL;
        boolean success = false;
        try {
            // Create OpenSSLConfCmd context if used
            OpenSSLConf openSslConf = sslHostConfig.getOpenSslConf();
            if (openSslConf != null) {
                try {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("openssl.makeConf"));
                    }
                    // FIXME: reimplement
                    /*
                    cctx = SSLConf.make(aprPool,
                                        SSL.SSL_CONF_FLAG_FILE |
                                        SSL.SSL_CONF_FLAG_SERVER |
                                        SSL.SSL_CONF_FLAG_CERTIFICATE |
                                        SSL.SSL_CONF_FLAG_SHOW_ERRORS);*/
                } catch (Exception e) {
                    throw new SSLException(sm.getString("openssl.errMakeConf"), e);
                }
            }

            // SSL protocol
            // FIXME: According to the OpenSSL documentation, this is a really
            // bad idea, and every call is deprecated. Instead, using the
            // auto TLS_server_method is heavily recommended. Also TLSv1_3_server_method
            // is apparently not part of the public API.
            /*
            int value = SSL.SSL_PROTOCOL_NONE;
            for (String protocol : sslHostConfig.getEnabledProtocols()) {
                if (Constants.SSL_PROTO_SSLv2Hello.equalsIgnoreCase(protocol)) {
                    // NO-OP. OpenSSL always supports SSLv2Hello
                } else if (Constants.SSL_PROTO_SSLv2.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_SSLV2;
                } else if (Constants.SSL_PROTO_SSLv3.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_SSLV3;
                } else if (Constants.SSL_PROTO_TLSv1.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_TLSV1;
                } else if (Constants.SSL_PROTO_TLSv1_1.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_TLSV1_1;
                } else if (Constants.SSL_PROTO_TLSv1_2.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_TLSV1_2;
                } else if (Constants.SSL_PROTO_TLSv1_3.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_TLSV1_3;
                } else if (Constants.SSL_PROTO_ALL.equalsIgnoreCase(protocol)) {
                    value |= SSL.SSL_PROTOCOL_ALL;
                } else {
                    // Should not happen since filtering to build
                    // enabled protocols removes invalid values.
                    throw new Exception(netSm.getString(
                            "endpoint.apr.invalidSslProtocol", protocol));
                }
            }*/

            ctx = SSL_CTX_new(TLS_server_method());

            this.negotiableProtocols = negotiableProtocols;

            success = true;
        } catch(Exception e) {
            throw new SSLException(sm.getString("openssl.errorSSLCtxInit"), e);
        } finally {
            state = new OpenSSLState(scope, cctx, ctx);
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


    protected static boolean checkConf(OpenSSLConf conf, MemoryAddress cctx) throws Exception {
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
            try {
                rc = SSLConf.check(cctx, name, value);
            } catch (Exception e) {
                log.error(sm.getString("opensslconf.checkFailed"));
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

    protected static boolean applyConf(OpenSSLConf conf, MemoryAddress cctx, MemoryAddress ctx) throws Exception {
        boolean result = true;
        SSLConf.assign(cctx, ctx);
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
            try {
                rc = SSLConf.apply(cctx, name, value);
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
        rc = SSLConf.finish(cctx);
        if (rc <= 0) {
            log.error(sm.getString("opensslconf.finishFailed", Integer.toString(rc)));
            result = false;
        }
        if (!result) {
            log.error(sm.getString("opensslconf.applyFailed"));
        }
        return result;
    }

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
                value = SSL_VERIFY_PEER() | SSL_VERIFY_FAIL_IF_NO_PEER_CERT();
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
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            MethodHandle verifyCertificateHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackVerify",
                    MethodType.methodType(int.class, int.class, MemoryAddress.class));
            verifyCertificateHandle = verifyCertificateHandle.bindTo(this);
            NativeSymbol verifyCallback = CLinker.systemCLinker().upcallStub(verifyCertificateHandle,
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), state.scope);
            SSL_CTX_set_verify(state.ctx, value, verifyCallback);

            // FIXME: Implement trust and certificate verification
            if (tms != null) {
                // Client certificate verification based on custom trust managers
                x509TrustManager = chooseTrustManager(tms);
                MethodHandle certVerifyCallbackHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackCertVerify",
                        MethodType.methodType(int.class, MemoryAddress.class, MemoryAddress.class));
                certVerifyCallbackHandle = certVerifyCallbackHandle.bindTo(this);
                NativeSymbol certVerifyCallback = CLinker.systemCLinker().upcallStub(verifyCertificateHandle,
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS), state.scope);
                SSL_CTX_set_cert_verify_callback(state.ctx, certVerifyCallback, MemoryAddress.NULL);

                // Pass along the DER encoded certificates of the accepted client
                // certificate issuers, so that their subjects can be presented
                // by the server during the handshake to allow the client choosing
                // an acceptable certificate
                for (X509Certificate caCert : x509TrustManager.getAcceptedIssuers()) {
                    SSLContext.addClientCACertificateRaw(state.ctx, caCert.getEncoded());
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("openssl.addedClientCaCert", caCert.toString()));
                    }
                }
            } else {
                // Client certificate verification based on trusted CA files and dirs
                SSLContext.setCACertificate(state.ctx,
                        SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificateFile()),
                        SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificatePath()));
            }

            if (negotiableProtocols != null && negotiableProtocols.size() > 0) {
                List<String> protocols = new ArrayList<>(negotiableProtocols);
                protocols.add("http/1.1");
                negotiableProtocolsArray = protocols.toArray(new String[0]);

                // int openSSLCallbackAlpnSelectProto(MemoryAddress ssl, MemoryAddress out, MemoryAddress outlen,
                //        MemoryAddress in, int inlen, MemoryAddress arg
                MethodHandle alpnSelectProtoCallbackHandle = lookup.findVirtual(OpenSSLContext.class, "openSSLCallbackAlpnSelectProto",
                        MethodType.methodType(int.class, MemoryAddress.class, MemoryAddress.class,
                                MemoryAddress.class, MemoryAddress.class, int.class, MemoryAddress.class));
                alpnSelectProtoCallbackHandle = alpnSelectProtoCallbackHandle.bindTo(this);
                NativeSymbol alpnSelectProtoCallback = CLinker.systemCLinker().upcallStub(alpnSelectProtoCallbackHandle,
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS
                                , ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), state.scope);
                SSL_CTX_set_alpn_select_cb(state.ctx, alpnSelectProtoCallback, MemoryAddress.NULL);

                // FIXME: Implement NPN (annoying and likely not useful anymore)
                //SSLContext.setNpnProtos(state.ctx, protocolsArray, SSL.SSL_SELECTOR_FAILURE_NO_ADVERTISE);
            }

            // FIXME: reimplement
            // Apply OpenSSLConfCmd if used
            OpenSSLConf openSslConf = sslHostConfig.getOpenSslConf();
            if (openSslConf != null && !MemoryAddress.NULL.equals(state.cctx)) {
                // Check OpenSSLConfCmd if used
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("openssl.checkConf"));
                }
                try {
                    if (!checkConf(openSslConf, state.cctx)) {
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
                    if (!applyConf(openSslConf, state.cctx, state.ctx)) {
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


    // int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
    //        const unsigned char *in, unsigned int inlen, void *arg)
    public int openSSLCallbackAlpnSelectProto(MemoryAddress ssl, MemoryAddress out, MemoryAddress outlen,
            MemoryAddress in, int inlen, MemoryAddress arg) {
        // FIXME: implement ALPN
        return SSL_TLSEXT_ERR_NOACK();
    }

    public int openSSLCallbackVerify(int preverify_ok, MemoryAddress /*X509_STORE_CTX*/ x509_ctx) {
        MemoryAddress ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        //HandshakeState handshakeState = handshakeStateMap.get(Long.valueOf(ssl.address().toRawLongValue()));
        int ok = preverify_ok;
        int errnum = X509_STORE_CTX_get_error(x509_ctx);
        int errdepth = X509_STORE_CTX_get_error_depth(x509_ctx);
        if (certificateVerifyMode == -1 /*SSL_CVERIFY_UNSET*/
                || certificateVerifyMode == SSL_VERIFY_NONE()) {
            return 1;
        }
        /*SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) -> ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) \
                || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) \
                || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) \
                || (errnum == X509_V_ERR_CERT_UNTRUSTED) \
                || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))*/
        if ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT())
                || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN())
                || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY())
                || (errnum == X509_V_ERR_CERT_UNTRUSTED())
                || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE()) &&
                (certificateVerifyMode == (SSL_VERIFY_PEER()
                        | SSL_VERIFY_FAIL_IF_NO_PEER_CERT()))) {
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
            X509_STORE_CTX_set_error(x509_ctx, -1);
        }
        // FIXME: Implement OCSP again
        // FIXME: GLORIOUS PURPOSE !!!!!
        if (ok == 0) {
            // FIXME: debug logging
        }
        if (errdepth > sslHostConfig.getCertificateVerificationDepth()) {
            // Certificate Verification: Certificate Chain too long
            ok = 0;
        }
        return ok;
    }


    public int openSSLCallbackCertVerify(MemoryAddress /*X509_STORE_CTX*/ x509_ctx, MemoryAddress param) {
        MemoryAddress ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        MemoryAddress /*STACK_OF(X509)*/ sk = X509_STORE_CTX_get0_untrusted(x509_ctx);
        int len = sk_X509_num(sk);
        byte[][] certificateChain = new byte[len][];
        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            for (int i = 0; i < len; i++) {
                MemoryAddress/*(X509*)*/ certificatePointer = sk_X509_value(sk, i);
                MemorySegment bufPointer = allocator.allocate(ValueLayout.ADDRESS);
                int length = i2d_X509(certificatePointer, bufPointer);
                if (length < 0) {
                    certificateChain[i] = new byte[0];
                    CRYPTO_free(bufPointer, OPENSSL_FILE(), OPENSSL_LINE()); // OPENSSL_free macro
                    continue;
                }
                byte[] certificate = new byte[length];
                for (int j = 0; j < length; j++) {
                    certificate[j] = certificatePointer.get(ValueLayout.JAVA_BYTE, j);
                }
                certificateChain[i] = certificate;
                CRYPTO_free(bufPointer, OPENSSL_FILE(), OPENSSL_LINE()); // OPENSSL_free macro
            }
            SSL_get_current_cipher(ssl); // FIXME: SSL_CIPHER_authentication_method(SSL_get_current_cipher(ssl)) !
            String authMethod = "UNKNOWN";
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


    public void addCertificate(SSLHostConfigCertificate certificate) throws Exception {
        // Load Server key and certificate
        if (certificate.getCertificateFile() != null) {
            try (var scope = ResourceScope.newConfinedScope()) {
                var allocator = SegmentAllocator.nativeAllocator(scope);
                // Set certificate
                SSLContext.setCertificate(state.ctx,
                        SSLHostConfig.adjustRelativePath(certificate.getCertificateFile()),
                        SSLHostConfig.adjustRelativePath(certificate.getCertificateKeyFile()),
                        certificate.getCertificateKeyPassword(), getCertificateIndex(certificate));
                // Set certificate chain file
                var certificateChainFileNative = allocator.allocateUtf8String(SSLHostConfig.adjustRelativePath(certificate.getCertificateChainFile()));
                // SSLContext.setCertificateChainFile(state.ctx,
                //        SSLHostConfig.adjustRelativePath(certificate.getCertificateChainFile()), false);
                if (SSL_CTX_use_certificate_chain_file(state.ctx, certificateChainFileNative) <= 0) {
                    // FIXME: log error
                }
                // Set revocation
                SSLContext.setCARevocation(state.ctx,
                        SSLHostConfig.adjustRelativePath(
                                sslHostConfig.getCertificateRevocationListFile()),
                        SSLHostConfig.adjustRelativePath(
                                sslHostConfig.getCertificateRevocationListPath()));
            }
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
            SSLContext.setCertificateRaw(state.ctx, chain[0].getEncoded(),
                    sb.toString().getBytes(StandardCharsets.US_ASCII),
                    getCertificateIndex(certificate));
            for (int i = 1; i < chain.length; i++) {
                SSLContext.addChainCertificateRaw(state.ctx, chain[i].getEncoded());
            }
        }
    }


    private static int getCertificateIndex(SSLHostConfigCertificate certificate) {
        int result;
        // If the type is undefined there will only be one certificate (enforced
        // in SSLHostConfig) so use the RSA slot.
        if (certificate.getType() == Type.RSA || certificate.getType() == Type.UNDEFINED) {
            result = SSL.SSL_AIDX_RSA;
        } else if (certificate.getType() == Type.EC) {
            result = SSL.SSL_AIDX_ECC;
        } else if (certificate.getType() == Type.DSA) {
            result = SSL.SSL_AIDX_DSA;
        } else {
            result = SSL.SSL_AIDX_MAX;
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

        private OpenSSLState(ResourceScope scope, MemoryAddress cctx, MemoryAddress ctx) {
            this.scope = scope;
            this.cctx = cctx;
            this.ctx = ctx;
        }

        @Override
        public void run() {
            try {
            // FIXME: Cleanup
                SSL_free(ctx);
            /*
            if (ctx != null) {
                SSLContext.free(ctx);
            }
            if (cctx != 0) {
                SSLConf.free(cctx);
            }
            if (aprPool != 0) {
                Pool.destroy(aprPool);
            }*/
            } finally {
                scope.close();
            }
        }
    }
}
