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

import static org.apache.tomcat.util.openssl.openssl_h.CRYPTO_set_mem_functions;

import java.lang.foreign.Addressable;
import java.lang.foreign.CLinker;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryAddress;
import java.lang.foreign.NativeSymbol;
import java.lang.foreign.ResourceScope;
import java.lang.foreign.SegmentAllocator;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Provides memory allocation for OpenSSL through Panama APIs.
 */
public class OpenSSLAllocator {

    private static final Log log = LogFactory.getLog(OpenSSLAllocator.class);

    private static ThreadLocal<ResourceScope> localScope = new ThreadLocal<>();
    private static Map<Long, Allocation> allocations;
    static class Allocation {
        final long address;
        final long size;
        final String scopeId;
        final String file;
        final int line;
        Allocation(long address, long size, String scopeId, String file, int line) {
            this.address = address;
            this.size = size;
            this.scopeId = scopeId;
            this.file = file;
            this.line = line;
        }
        @Override
        public String toString() {
            return "Allocation at [" + address + "] size " + size + " from [" + file + "] at " + line;
        }
    }

    private static final MethodHandle openSSLCallbackMallocHandle;
    private static final MethodHandle openSSLCallbackReallocHandle;
    private static final MethodHandle openSSLCallbackFreeHandle;

    private static final FunctionDescriptor openSSLCallbackMallocFunctionDescriptor =
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT);
    private static final FunctionDescriptor openSSLCallbackReallocFunctionDescriptor =
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT);
    private static final FunctionDescriptor openSSLCallbackFreeFunctionDescriptor =
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT);

    static {
        MethodHandles.Lookup lookup = MethodHandles.lookup();
        try {
            openSSLCallbackMallocHandle = lookup.findStatic(OpenSSLAllocator.class, "openSSLCallbackMalloc",
                    MethodType.methodType(Addressable.class, long.class, MemoryAddress.class, int.class));
            openSSLCallbackReallocHandle = lookup.findStatic(OpenSSLAllocator.class, "openSSLCallbackRealloc",
                    MethodType.methodType(Addressable.class, MemoryAddress.class, long.class, MemoryAddress.class, int.class));
            openSSLCallbackFreeHandle = lookup.findStatic(OpenSSLAllocator.class, "openSSLCallbackFree",
                    MethodType.methodType(void.class, MemoryAddress.class, MemoryAddress.class, int.class));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static void init() {
        // int CRYPTO_set_mem_functions(
        //        void *(*m)(size_t, const char *, int),
        //        void *(*r)(void *, size_t, const char *, int),
        //        void (*f)(void *, const char *, int))
        NativeSymbol openSSLCallbackMalloc = CLinker.systemCLinker().upcallStub(openSSLCallbackMallocHandle,
                openSSLCallbackMallocFunctionDescriptor, ResourceScope.globalScope());
        NativeSymbol openSSLCallbackRealloc = CLinker.systemCLinker().upcallStub(openSSLCallbackReallocHandle,
                openSSLCallbackReallocFunctionDescriptor, ResourceScope.globalScope());
        NativeSymbol openSSLCallbackFree = CLinker.systemCLinker().upcallStub(openSSLCallbackFreeHandle,
                openSSLCallbackFreeFunctionDescriptor, ResourceScope.globalScope());
        int res = CRYPTO_set_mem_functions(openSSLCallbackMalloc, openSSLCallbackRealloc, openSSLCallbackFree);
        if (log.isDebugEnabled()) {
            log.debug("CRYPTO_set_mem_functions done, result: " + res);
        }
    }

    static void destroy() {
    }

    static ResourceScope enterScope(ResourceScope scope) {
        ResourceScope oldScope = localScope.get();
        localScope.set(scope);
        return oldScope;
    }

    static void exitScope(ResourceScope oldScope) {
        localScope.set(oldScope);
    }

    static synchronized void startTracking() {
        allocations = new ConcurrentHashMap<>();
    }

    static synchronized void stopTracking() {
        for (Allocation allocation : allocations.values()) {
            System.out.println(allocation);
        }
        allocations = null;
    }

    static synchronized Addressable openSSLCallbackMalloc(long size, MemoryAddress file, int line) {
        ResourceScope scope = localScope.get();
        if (log.isDebugEnabled()) {
            log.debug(scope + "] malloc(" + size + ") from: "
                    + ((MemoryAddress.NULL.equals(file)) ? null : file.getUtf8String(0)) + " at " + line);
        }
        if (scope == null) {
            scope = ResourceScope.globalScope();
        }
        // Allocate desired size from the corresponding scope
        Addressable allocation = SegmentAllocator.nativeAllocator(scope).allocate(size);
        if (size == ValueLayout.ADDRESS.byteSize()) {
            // Set to zero, just in case
            allocation.address().set(ValueLayout.ADDRESS, 0, MemoryAddress.NULL);
        }
        if (allocations != null) {
            Long address = Long.valueOf(allocation.address().toRawLongValue());
            allocations.put(address, new Allocation(address, Long.valueOf(size), (scope != null) ? scope.toString() : "",
                    ((MemoryAddress.NULL.equals(file)) ? null : file.getUtf8String(0)), line));
        }
        return allocation;
    }


    static synchronized Addressable openSSLCallbackRealloc(MemoryAddress buf, long size, MemoryAddress file, int line) {
        ResourceScope scope = localScope.get();
        if (log.isDebugEnabled()) {
            log.debug(scope + "] realloc[" + buf + "](" + size + ") from: "
                    + ((MemoryAddress.NULL.equals(file)) ? null : file.getUtf8String(0)) + " at " + line);
        }
        if (scope == null) {
            scope = ResourceScope.globalScope();
        }
        // Effectively this is a malloc since free is delayed until the associated scope is closed
        Addressable allocation = SegmentAllocator.nativeAllocator(scope).allocate(size);
        if (allocations != null) {
            Long address = Long.valueOf(allocation.address().toRawLongValue());
            allocations.put(address, new Allocation(address, Long.valueOf(size), scope.toString(),
                    ((MemoryAddress.NULL.equals(file)) ? null : file.getUtf8String(0)), line));
        }
        return allocation;
    }


    static synchronized void openSSLCallbackFree(MemoryAddress buf, MemoryAddress file, int line) {
        ResourceScope scope = localScope.get();
        if (log.isDebugEnabled()) {
            log.debug(scope + "] free[" + buf + "] from: "
                    + ((MemoryAddress.NULL.equals(file)) ? null : file.getUtf8String(0)) + " at " + line);
        }
        if (allocations != null && !MemoryAddress.NULL.equals(buf)) {
            Long address = Long.valueOf(buf.address().toRawLongValue());
            Allocation allocation = allocations.remove(address);
            if (allocation != null) {
                String scopeId = (scope == null) ? "" : scope.toString();
                if (!scopeId.equals(allocation.scopeId)) {
                    // Add back because different context
                    allocations.put(address, allocation);
                }
            } else {
                // This seems weird
            }
        }
    }

}
