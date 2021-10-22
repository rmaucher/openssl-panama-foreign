/**
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net.openssl.panama;

import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.ResourceScope;
import jdk.incubator.foreign.SegmentAllocator;

import static org.apache.tomcat.util.openssl.openssl_h.*;

public class HelloOpenSSL {

    public static void main(String[] args) {
        MemoryAddress ssl = MemoryAddress.NULL;
        MemoryAddress sslCtx = MemoryAddress.NULL;
        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN(), MemoryAddress.NULL);
            System.out.println("Using " + OPENSSL_VERSION_TEXT().getUtf8String(0));
            sslCtx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_set_options(sslCtx, SSL_OP_ALL());
            SSL_CTX_set_cipher_list(sslCtx, allocator.allocateUtf8String("ALL"));
            ssl = SSL_new(sslCtx);
            SSL_set_accept_state(ssl);
            MemoryAddress sk = SSL_get_ciphers(ssl);
            int len = OPENSSL_sk_num(sk);
            if (len <= 0) {
                return;
            }
            for (int i = 0; i < len; i++) {
                var cipher = OPENSSL_sk_value(sk, i);
                var cipherName = SSL_CIPHER_get_name(cipher);
                System.out.println("Cipher: " + cipherName.getUtf8String(0));
            }
            System.out.println("Handshake: " + SSL_do_handshake(ssl));
        } finally {
            if (!MemoryAddress.NULL.equals(ssl)) {
                System.out.println("SSL_free " + ssl.toRawLongValue());
                SSL_free(ssl);
            }
            if (!MemoryAddress.NULL.equals(sslCtx)) {
                System.out.println("SSL_free CTX " + sslCtx.toRawLongValue());
                //SSL_free(sslCtx);
            }
        }
    }

}
