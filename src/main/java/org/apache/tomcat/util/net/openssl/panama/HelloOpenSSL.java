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
        try (var scope = ResourceScope.newConfinedScope()) {
            var allocator = SegmentAllocator.nativeAllocator(scope);
            var sslCtx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_set_options(sslCtx, SSL_OP_ALL());
            SSL_CTX_set_cipher_list(sslCtx, allocator.allocateUtf8String("ALL"));
            var ssl = SSL_new(sslCtx);
            SSL_set_accept_state(ssl);
            MemoryAddress sk = SSL_get_ciphers(ssl);
            int len = OPENSSL_sk_num(sk);
            if (len <= 0) {
                return;
            }
            for (int i = 0; i < len; i++) {
                MemoryAddress cipher = OPENSSL_sk_value(sk, i);
                MemoryAddress cipherName = SSL_CIPHER_get_name(cipher);
                System.out.println("Cipher: " + cipherName.getUtf8String(0));
            }
        }
    }

}
