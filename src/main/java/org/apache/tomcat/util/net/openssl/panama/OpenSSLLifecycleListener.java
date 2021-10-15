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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.jni.Library;
import org.apache.tomcat.jni.LibraryNotFoundError;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.res.StringManager;



/**
 * Implementation of <code>LifecycleListener</code> that will do the global
 * initialization of OpenSSL according to specified configuration parameters.
 */
public class OpenSSLLifecycleListener implements LifecycleListener {

    private static final Log log = LogFactory.getLog(OpenSSLLifecycleListener.class);
    /**
     * Info messages during init() are cached until Lifecycle.BEFORE_INIT_EVENT
     * so that, in normal (non-error) cases, init() related log messages appear
     * at the expected point in the lifecycle.
     */
    private static final List<String> initInfoLogMessages = new ArrayList<>(3);

    /**
     * The string manager for this package.
     */
    protected static final StringManager sm = StringManager.getManager(OpenSSLLifecycleListener.class);


    // ---------------------------------------------- Constants


    protected static final int TCN_REQUIRED_MAJOR = 1;
    protected static final int TCN_REQUIRED_MINOR = 2;
    protected static final int TCN_REQUIRED_PATCH = 14;
    protected static final int TCN_RECOMMENDED_MINOR = 2;
    protected static final int TCN_RECOMMENDED_PV = 30;


    // ---------------------------------------------- Properties
    protected static String SSLEngine = "on"; //default on
    protected static String FIPSMode = "off"; // default off, valid only when SSLEngine="on"
    protected static String SSLRandomSeed = "builtin";
    protected static boolean sslInitialized = false;
    protected static boolean fipsModeActive = false;

    /**
     * The "FIPS mode" level that we use as the argument to OpenSSL method
     * <code>FIPS_mode_set()</code> to enable FIPS mode and that we expect as
     * the return value of <code>FIPS_mode()</code> when FIPS mode is enabled.
     * <p>
     * In the future the OpenSSL library might grow support for different
     * non-zero "FIPS" modes that specify different allowed subsets of ciphers
     * or whatever, but nowadays only "1" is the supported value.
     * </p>
     * @see <a href="http://wiki.openssl.org/index.php/FIPS_mode_set%28%29">OpenSSL method FIPS_mode_set()</a>
     * @see <a href="http://wiki.openssl.org/index.php/FIPS_mode%28%29">OpenSSL method FIPS_mode()</a>
     */
    private static final int FIPS_ON = 1;

    private static final int FIPS_OFF = 0;

    protected static final Object lock = new Object();

    public static boolean isAprAvailable() {
        //https://bz.apache.org/bugzilla/show_bug.cgi?id=48613
        if (OpenSSLStatus.isInstanceCreated()) {
            synchronized (lock) {
                init();
            }
        }
        return OpenSSLStatus.isAvailable();
    }

    public OpenSSLLifecycleListener() {
        OpenSSLStatus.setInstanceCreated(true);
    }

    // ---------------------------------------------- LifecycleListener Methods

    /**
     * Primary entry point for startup and shutdown events.
     *
     * @param event The event that has occurred
     */
    @Override
    public void lifecycleEvent(LifecycleEvent event) {

        if (Lifecycle.BEFORE_INIT_EVENT.equals(event.getType())) {
            synchronized (lock) {
                init();
                for (String msg : initInfoLogMessages) {
                    log.info(msg);
                }
                initInfoLogMessages.clear();
                if (OpenSSLStatus.isAvailable()) {
                    try {
                        initializeSSL();
                    } catch (Throwable t) {
                        t = ExceptionUtils.unwrapInvocationTargetException(t);
                        ExceptionUtils.handleThrowable(t);
                        log.error(sm.getString("aprListener.sslInit"), t);
                    }
                }
                // Failure to initialize FIPS mode is fatal
                if (!(null == FIPSMode || "off".equalsIgnoreCase(FIPSMode)) && !isFIPSModeActive()) {
                    String errorMessage = sm.getString("aprListener.initializeFIPSFailed");
                    Error e = new Error(errorMessage);
                    // Log here, because thrown error might be not logged
                    log.fatal(errorMessage, e);
                    throw e;
                }
            }
        } else if (Lifecycle.AFTER_DESTROY_EVENT.equals(event.getType())) {
            synchronized (lock) {
                if (!OpenSSLStatus.isAvailable()) {
                    return;
                }
                try {
                    terminateAPR();
                } catch (Throwable t) {
                    t = ExceptionUtils.unwrapInvocationTargetException(t);
                    ExceptionUtils.handleThrowable(t);
                    log.info(sm.getString("aprListener.aprDestroy"));
                }
            }
        }

    }

    private static void terminateAPR()
        throws ClassNotFoundException, NoSuchMethodException,
               IllegalAccessException, InvocationTargetException
    {
        String methodName = "terminate";
        Method method = Class.forName("org.apache.tomcat.jni.Library")
            .getMethod(methodName, (Class [])null);
        method.invoke(null, (Object []) null);
        OpenSSLStatus.setAvailable(false);
        OpenSSLStatus.setInitialized(false);
        sslInitialized = false; // Well we cleaned the pool in terminate.
        fipsModeActive = false;
    }

    private static void init()
    {
        int major = 0;
        int minor = 0;
        int patch = 0;
        int apver = 0;
        int rqver = TCN_REQUIRED_MAJOR * 1000 + TCN_REQUIRED_MINOR * 100 + TCN_REQUIRED_PATCH;
        int rcver = TCN_REQUIRED_MAJOR * 1000 + TCN_RECOMMENDED_MINOR * 100 + TCN_RECOMMENDED_PV;

        if (OpenSSLStatus.isInitialized()) {
            return;
        }
        OpenSSLStatus.setInitialized(true);

        try {
            Library.initialize(null);
            major = Library.TCN_MAJOR_VERSION;
            minor = Library.TCN_MINOR_VERSION;
            patch = Library.TCN_PATCH_VERSION;
            apver = major * 1000 + minor * 100 + patch;
        } catch (LibraryNotFoundError lnfe) {
            // Library not on path
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("aprListener.aprInitDebug",
                        lnfe.getLibraryNames(), System.getProperty("java.library.path"),
                        lnfe.getMessage()), lnfe);
            }
            initInfoLogMessages.add(sm.getString("aprListener.aprInit",
                    System.getProperty("java.library.path")));
            return;
        } catch (Throwable t) {
            // Library present but failed to load
            t = ExceptionUtils.unwrapInvocationTargetException(t);
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("aprListener.aprInitError", t.getMessage()), t);
            return;
        }
        if (apver < rqver) {
            log.error(sm.getString("aprListener.tcnInvalid",
                    Library.versionString(),
                    TCN_REQUIRED_MAJOR + "." +
                    TCN_REQUIRED_MINOR + "." +
                    TCN_REQUIRED_PATCH));
            try {
                // Terminate the APR in case the version
                // is below required.
                terminateAPR();
            } catch (Throwable t) {
                t = ExceptionUtils.unwrapInvocationTargetException(t);
                ExceptionUtils.handleThrowable(t);
            }
            return;
        }
        if (apver < rcver) {
            initInfoLogMessages.add(sm.getString("aprListener.tcnVersion",
                    Library.versionString(),
                    TCN_REQUIRED_MAJOR + "." +
                    TCN_RECOMMENDED_MINOR + "." +
                    TCN_RECOMMENDED_PV));
        }

        initInfoLogMessages.add(sm.getString("aprListener.tcnValid",
                Library.versionString(),
                Library.aprVersionString()));

        // Log APR flags
        initInfoLogMessages.add(sm.getString("aprListener.flags",
                Boolean.valueOf(Library.APR_HAVE_IPV6),
                Boolean.valueOf(Library.APR_HAS_SENDFILE),
                Boolean.valueOf(Library.APR_HAS_SO_ACCEPTFILTER),
                Boolean.valueOf(Library.APR_HAS_RANDOM),
                Boolean.valueOf(Library.APR_HAVE_UNIX)));

        OpenSSLStatus.setAvailable(true);
    }

    private static void initializeSSL() throws Exception {

        if ("off".equalsIgnoreCase(SSLEngine)) {
            return;
        }
        if (sslInitialized) {
             //only once per VM
            return;
        }

        sslInitialized = true;

        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);

            // FIXME: SSL.randSet with SSLRandomSeed

            // FIXME: implement ssl_init_cleanup to use if there's an error or when the library is unloaded

            // Main library init
            OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN(), MemoryAddress.NULL);

            // Setup engine
            String engineName = "on".equalsIgnoreCase(SSLEngine) ? null : SSLEngine;
            if (engineName != null) {
                if ("auto".equals(engineName)) {
                    ENGINE_register_all_complete();
                } else {
                    var engine = allocator.allocateUtf8String(engineName);
                    var enginePointer = ENGINE_by_id(engine);
                    if (MemoryAddress.NULL.equals(enginePointer)) {
                        enginePointer = ENGINE_by_id(allocator.allocateUtf8String("dynamic"));
                        if (enginePointer != null) {
                            if (ENGINE_ctrl_cmd_string(enginePointer, allocator.allocateUtf8String("SO_PATH"), engine, 0) == 0
                                    || ENGINE_ctrl_cmd_string(enginePointer, allocator.allocateUtf8String("LOAD"),
                                            MemoryAddress.NULL, 0) == 0) {
                                // Engine load error
                                ENGINE_free(enginePointer);
                                enginePointer = MemoryAddress.NULL;
                            }
                        }
                    }
                    if (!MemoryAddress.NULL.equals(enginePointer)) {
                        if (ENGINE_set_default(enginePointer, ENGINE_METHOD_ALL()) == 0) {
                            // Engine load error
                            ENGINE_free(enginePointer);
                            enginePointer = MemoryAddress.NULL;
                        }
                    }
                    if (MemoryAddress.NULL.equals(enginePointer)) {
                        // FIXME: throw error here
                    }
                }
            }

            // Random seed, translated to the Java way
            // FIXME

            // FIXME: Init app data (FIXME: find out if it is needed)

            // FIXME: Init DH paramaters

            // FIXME: Keylog callback ?

            if (!(null == FIPSMode || "off".equalsIgnoreCase(FIPSMode))) {

                fipsModeActive = false;

                final boolean enterFipsMode;
                int fipsModeState = FIPS_mode();

                if(log.isDebugEnabled()) {
                    log.debug(sm.getString("aprListener.currentFIPSMode",
                                           Integer.valueOf(fipsModeState)));
                }

                if ("on".equalsIgnoreCase(FIPSMode)) {
                    if (fipsModeState == FIPS_ON) {
                        log.info(sm.getString("aprListener.skipFIPSInitialization"));
                        fipsModeActive = true;
                        enterFipsMode = false;
                    } else {
                        enterFipsMode = true;
                    }
                } else if ("require".equalsIgnoreCase(FIPSMode)) {
                    if (fipsModeState == FIPS_ON) {
                        fipsModeActive = true;
                        enterFipsMode = false;
                    } else {
                        throw new IllegalStateException(
                                sm.getString("aprListener.requireNotInFIPSMode"));
                    }
                } else if ("enter".equalsIgnoreCase(FIPSMode)) {
                    if (fipsModeState == FIPS_OFF) {
                        enterFipsMode = true;
                    } else {
                        throw new IllegalStateException(sm.getString(
                                "aprListener.enterAlreadyInFIPSMode",
                                Integer.valueOf(fipsModeState)));
                    }
                } else {
                    throw new IllegalArgumentException(sm.getString(
                            "aprListener.wrongFIPSMode", FIPSMode));
                }

                if (enterFipsMode) {
                    log.info(sm.getString("aprListener.initializingFIPS"));

                    fipsModeState = FIPS_mode_set(FIPS_ON);
                    if (fipsModeState != FIPS_ON) {
                        // This case should be handled by the native method,
                        // but we'll make absolutely sure, here.
                        String message = sm.getString("aprListener.initializeFIPSFailed");
                        log.error(message);
                        throw new IllegalStateException(message);
                    }

                    fipsModeActive = true;
                    log.info(sm.getString("aprListener.initializeFIPSSuccess"));
                }
            }

        }

        log.info(sm.getString("aprListener.initializedOpenSSL", SSL.versionString()));
    }

    public String getSSLEngine() {
        return SSLEngine;
    }

    public void setSSLEngine(String SSLEngine) {
        if (!SSLEngine.equals(OpenSSLLifecycleListener.SSLEngine)) {
            // Ensure that the SSLEngine is consistent with that used for SSL init
            if (sslInitialized) {
                throw new IllegalStateException(
                        sm.getString("aprListener.tooLateForSSLEngine"));
            }

            OpenSSLLifecycleListener.SSLEngine = SSLEngine;
        }
    }

    public String getSSLRandomSeed() {
        return SSLRandomSeed;
    }

    public void setSSLRandomSeed(String SSLRandomSeed) {
        if (!SSLRandomSeed.equals(OpenSSLLifecycleListener.SSLRandomSeed)) {
            // Ensure that the random seed is consistent with that used for SSL init
            if (sslInitialized) {
                throw new IllegalStateException(
                        sm.getString("aprListener.tooLateForSSLRandomSeed"));
            }

            OpenSSLLifecycleListener.SSLRandomSeed = SSLRandomSeed;
        }
    }

    public String getFIPSMode() {
        return FIPSMode;
    }

    public void setFIPSMode(String FIPSMode) {
        if (!FIPSMode.equals(OpenSSLLifecycleListener.FIPSMode)) {
            // Ensure that the FIPS mode is consistent with that used for SSL init
            if (sslInitialized) {
                throw new IllegalStateException(
                        sm.getString("aprListener.tooLateForFIPSMode"));
            }

            OpenSSLLifecycleListener.FIPSMode = FIPSMode;
        }
    }

    public boolean isFIPSModeActive() {
        return fipsModeActive;
    }

    public static boolean isInstanceCreated() {
        return OpenSSLStatus.isInstanceCreated();
    }

}
