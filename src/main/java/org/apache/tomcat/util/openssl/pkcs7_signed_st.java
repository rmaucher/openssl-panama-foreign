// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class pkcs7_signed_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("version"),
        ADDRESS.withName("md_algs"),
        ADDRESS.withName("cert"),
        ADDRESS.withName("crl"),
        ADDRESS.withName("signer_info"),
        ADDRESS.withName("contents")
    ).withName("pkcs7_signed_st");
    public static MemoryLayout $LAYOUT() {
        return pkcs7_signed_st.$struct$LAYOUT;
    }
    static final VarHandle version$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("version"));
    public static VarHandle version$VH() {
        return pkcs7_signed_st.version$VH;
    }
    public static MemoryAddress version$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.version$VH.get(seg);
    }
    public static void version$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_signed_st.version$VH.set(seg, x);
    }
    public static MemoryAddress version$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.version$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void version$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_signed_st.version$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle md_algs$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("md_algs"));
    public static VarHandle md_algs$VH() {
        return pkcs7_signed_st.md_algs$VH;
    }
    public static MemoryAddress md_algs$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.md_algs$VH.get(seg);
    }
    public static void md_algs$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_signed_st.md_algs$VH.set(seg, x);
    }
    public static MemoryAddress md_algs$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.md_algs$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void md_algs$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_signed_st.md_algs$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle cert$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("cert"));
    public static VarHandle cert$VH() {
        return pkcs7_signed_st.cert$VH;
    }
    public static MemoryAddress cert$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.cert$VH.get(seg);
    }
    public static void cert$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_signed_st.cert$VH.set(seg, x);
    }
    public static MemoryAddress cert$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.cert$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void cert$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_signed_st.cert$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle crl$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("crl"));
    public static VarHandle crl$VH() {
        return pkcs7_signed_st.crl$VH;
    }
    public static MemoryAddress crl$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.crl$VH.get(seg);
    }
    public static void crl$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_signed_st.crl$VH.set(seg, x);
    }
    public static MemoryAddress crl$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.crl$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void crl$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_signed_st.crl$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle signer_info$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("signer_info"));
    public static VarHandle signer_info$VH() {
        return pkcs7_signed_st.signer_info$VH;
    }
    public static MemoryAddress signer_info$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.signer_info$VH.get(seg);
    }
    public static void signer_info$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_signed_st.signer_info$VH.set(seg, x);
    }
    public static MemoryAddress signer_info$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.signer_info$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void signer_info$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_signed_st.signer_info$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle contents$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("contents"));
    public static VarHandle contents$VH() {
        return pkcs7_signed_st.contents$VH;
    }
    public static MemoryAddress contents$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.contents$VH.get(seg);
    }
    public static void contents$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_signed_st.contents$VH.set(seg, x);
    }
    public static MemoryAddress contents$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_signed_st.contents$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void contents$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_signed_st.contents$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment allocate(ResourceScope scope) { return allocate(SegmentAllocator.nativeAllocator(scope)); }
    public static MemorySegment allocateArray(int len, ResourceScope scope) {
        return allocateArray(len, SegmentAllocator.nativeAllocator(scope));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


