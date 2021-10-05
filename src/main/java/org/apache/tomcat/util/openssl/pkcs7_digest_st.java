// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class pkcs7_digest_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("version"),
        ADDRESS.withName("md"),
        ADDRESS.withName("contents"),
        ADDRESS.withName("digest")
    ).withName("pkcs7_digest_st");
    public static MemoryLayout $LAYOUT() {
        return pkcs7_digest_st.$struct$LAYOUT;
    }
    static final VarHandle version$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("version"));
    public static VarHandle version$VH() {
        return pkcs7_digest_st.version$VH;
    }
    public static MemoryAddress version$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.version$VH.get(seg);
    }
    public static void version$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_digest_st.version$VH.set(seg, x);
    }
    public static MemoryAddress version$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.version$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void version$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_digest_st.version$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle md$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("md"));
    public static VarHandle md$VH() {
        return pkcs7_digest_st.md$VH;
    }
    public static MemoryAddress md$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.md$VH.get(seg);
    }
    public static void md$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_digest_st.md$VH.set(seg, x);
    }
    public static MemoryAddress md$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.md$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void md$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_digest_st.md$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle contents$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("contents"));
    public static VarHandle contents$VH() {
        return pkcs7_digest_st.contents$VH;
    }
    public static MemoryAddress contents$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.contents$VH.get(seg);
    }
    public static void contents$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_digest_st.contents$VH.set(seg, x);
    }
    public static MemoryAddress contents$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.contents$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void contents$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_digest_st.contents$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle digest$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("digest"));
    public static VarHandle digest$VH() {
        return pkcs7_digest_st.digest$VH;
    }
    public static MemoryAddress digest$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.digest$VH.get(seg);
    }
    public static void digest$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_digest_st.digest$VH.set(seg, x);
    }
    public static MemoryAddress digest$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_digest_st.digest$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void digest$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_digest_st.digest$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

