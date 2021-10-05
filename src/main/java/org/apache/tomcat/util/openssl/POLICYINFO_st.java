// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class POLICYINFO_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("policyid"),
        ADDRESS.withName("qualifiers")
    ).withName("POLICYINFO_st");
    public static MemoryLayout $LAYOUT() {
        return POLICYINFO_st.$struct$LAYOUT;
    }
    static final VarHandle policyid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("policyid"));
    public static VarHandle policyid$VH() {
        return POLICYINFO_st.policyid$VH;
    }
    public static MemoryAddress policyid$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)POLICYINFO_st.policyid$VH.get(seg);
    }
    public static void policyid$set( MemorySegment seg, MemoryAddress x) {
        POLICYINFO_st.policyid$VH.set(seg, x);
    }
    public static MemoryAddress policyid$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)POLICYINFO_st.policyid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void policyid$set(MemorySegment seg, long index, MemoryAddress x) {
        POLICYINFO_st.policyid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle qualifiers$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("qualifiers"));
    public static VarHandle qualifiers$VH() {
        return POLICYINFO_st.qualifiers$VH;
    }
    public static MemoryAddress qualifiers$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)POLICYINFO_st.qualifiers$VH.get(seg);
    }
    public static void qualifiers$set( MemorySegment seg, MemoryAddress x) {
        POLICYINFO_st.qualifiers$VH.set(seg, x);
    }
    public static MemoryAddress qualifiers$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)POLICYINFO_st.qualifiers$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void qualifiers$set(MemorySegment seg, long index, MemoryAddress x) {
        POLICYINFO_st.qualifiers$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

