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

// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$23 {

    static final FunctionDescriptor SSL_CTX_set_tmp_dh_callback$dh$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle SSL_CTX_set_tmp_dh_callback$dh$MH = RuntimeHelper.downcallHandle(
        constants$23.SSL_CTX_set_tmp_dh_callback$dh$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_tmp_dh_callback$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_tmp_dh_callback$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_tmp_dh_callback",
        constants$23.SSL_CTX_set_tmp_dh_callback$FUNC, false
    );
    static final FunctionDescriptor SSL_CONF_CTX_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle SSL_CONF_CTX_new$MH = RuntimeHelper.downcallHandle(
        "SSL_CONF_CTX_new",
        constants$23.SSL_CONF_CTX_new$FUNC, false
    );
    static final FunctionDescriptor SSL_CONF_CTX_finish$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CONF_CTX_finish$MH = RuntimeHelper.downcallHandle(
        "SSL_CONF_CTX_finish",
        constants$23.SSL_CONF_CTX_finish$FUNC, false
    );
    static final FunctionDescriptor SSL_CONF_CTX_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle SSL_CONF_CTX_free$MH = RuntimeHelper.downcallHandle(
        "SSL_CONF_CTX_free",
        constants$23.SSL_CONF_CTX_free$FUNC, false
    );
    static final FunctionDescriptor SSL_CONF_CTX_set_flags$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_CONF_CTX_set_flags$MH = RuntimeHelper.downcallHandle(
        "SSL_CONF_CTX_set_flags",
        constants$23.SSL_CONF_CTX_set_flags$FUNC, false
    );
}


