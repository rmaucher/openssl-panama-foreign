// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class rsa_pss_params_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("hashAlgorithm"),
        ADDRESS.withName("maskGenAlgorithm"),
        ADDRESS.withName("saltLength"),
        ADDRESS.withName("trailerField"),
        ADDRESS.withName("maskHash")
    ).withName("rsa_pss_params_st");
    public static MemoryLayout $LAYOUT() {
        return rsa_pss_params_st.$struct$LAYOUT;
    }
    static final VarHandle hashAlgorithm$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("hashAlgorithm"));
    public static VarHandle hashAlgorithm$VH() {
        return rsa_pss_params_st.hashAlgorithm$VH;
    }
    public static MemoryAddress hashAlgorithm$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.hashAlgorithm$VH.get(seg);
    }
    public static void hashAlgorithm$set( MemorySegment seg, MemoryAddress x) {
        rsa_pss_params_st.hashAlgorithm$VH.set(seg, x);
    }
    public static MemoryAddress hashAlgorithm$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.hashAlgorithm$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void hashAlgorithm$set(MemorySegment seg, long index, MemoryAddress x) {
        rsa_pss_params_st.hashAlgorithm$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle maskGenAlgorithm$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("maskGenAlgorithm"));
    public static VarHandle maskGenAlgorithm$VH() {
        return rsa_pss_params_st.maskGenAlgorithm$VH;
    }
    public static MemoryAddress maskGenAlgorithm$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.maskGenAlgorithm$VH.get(seg);
    }
    public static void maskGenAlgorithm$set( MemorySegment seg, MemoryAddress x) {
        rsa_pss_params_st.maskGenAlgorithm$VH.set(seg, x);
    }
    public static MemoryAddress maskGenAlgorithm$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.maskGenAlgorithm$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void maskGenAlgorithm$set(MemorySegment seg, long index, MemoryAddress x) {
        rsa_pss_params_st.maskGenAlgorithm$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle saltLength$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("saltLength"));
    public static VarHandle saltLength$VH() {
        return rsa_pss_params_st.saltLength$VH;
    }
    public static MemoryAddress saltLength$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.saltLength$VH.get(seg);
    }
    public static void saltLength$set( MemorySegment seg, MemoryAddress x) {
        rsa_pss_params_st.saltLength$VH.set(seg, x);
    }
    public static MemoryAddress saltLength$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.saltLength$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void saltLength$set(MemorySegment seg, long index, MemoryAddress x) {
        rsa_pss_params_st.saltLength$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle trailerField$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("trailerField"));
    public static VarHandle trailerField$VH() {
        return rsa_pss_params_st.trailerField$VH;
    }
    public static MemoryAddress trailerField$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.trailerField$VH.get(seg);
    }
    public static void trailerField$set( MemorySegment seg, MemoryAddress x) {
        rsa_pss_params_st.trailerField$VH.set(seg, x);
    }
    public static MemoryAddress trailerField$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.trailerField$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void trailerField$set(MemorySegment seg, long index, MemoryAddress x) {
        rsa_pss_params_st.trailerField$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle maskHash$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("maskHash"));
    public static VarHandle maskHash$VH() {
        return rsa_pss_params_st.maskHash$VH;
    }
    public static MemoryAddress maskHash$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.maskHash$VH.get(seg);
    }
    public static void maskHash$set( MemorySegment seg, MemoryAddress x) {
        rsa_pss_params_st.maskHash$VH.set(seg, x);
    }
    public static MemoryAddress maskHash$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)rsa_pss_params_st.maskHash$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void maskHash$set(MemorySegment seg, long index, MemoryAddress x) {
        rsa_pss_params_st.maskHash$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


