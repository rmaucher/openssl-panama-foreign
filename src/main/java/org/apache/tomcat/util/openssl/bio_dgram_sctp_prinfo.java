// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class bio_dgram_sctp_prinfo {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_SHORT.withName("pr_policy"),
        MemoryLayout.paddingLayout(16),
        JAVA_INT.withName("pr_value")
    ).withName("bio_dgram_sctp_prinfo");
    public static MemoryLayout $LAYOUT() {
        return bio_dgram_sctp_prinfo.$struct$LAYOUT;
    }
    static final VarHandle pr_policy$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("pr_policy"));
    public static VarHandle pr_policy$VH() {
        return bio_dgram_sctp_prinfo.pr_policy$VH;
    }
    public static short pr_policy$get(MemorySegment seg) {
        return (short)bio_dgram_sctp_prinfo.pr_policy$VH.get(seg);
    }
    public static void pr_policy$set( MemorySegment seg, short x) {
        bio_dgram_sctp_prinfo.pr_policy$VH.set(seg, x);
    }
    public static short pr_policy$get(MemorySegment seg, long index) {
        return (short)bio_dgram_sctp_prinfo.pr_policy$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void pr_policy$set(MemorySegment seg, long index, short x) {
        bio_dgram_sctp_prinfo.pr_policy$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle pr_value$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("pr_value"));
    public static VarHandle pr_value$VH() {
        return bio_dgram_sctp_prinfo.pr_value$VH;
    }
    public static int pr_value$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_prinfo.pr_value$VH.get(seg);
    }
    public static void pr_value$set( MemorySegment seg, int x) {
        bio_dgram_sctp_prinfo.pr_value$VH.set(seg, x);
    }
    public static int pr_value$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_prinfo.pr_value$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void pr_value$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_prinfo.pr_value$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

