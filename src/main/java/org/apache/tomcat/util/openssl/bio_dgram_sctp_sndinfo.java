// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class bio_dgram_sctp_sndinfo {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_SHORT.withName("snd_sid"),
        JAVA_SHORT.withName("snd_flags"),
        JAVA_INT.withName("snd_ppid"),
        JAVA_INT.withName("snd_context")
    ).withName("bio_dgram_sctp_sndinfo");
    public static MemoryLayout $LAYOUT() {
        return bio_dgram_sctp_sndinfo.$struct$LAYOUT;
    }
    static final VarHandle snd_sid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("snd_sid"));
    public static VarHandle snd_sid$VH() {
        return bio_dgram_sctp_sndinfo.snd_sid$VH;
    }
    public static short snd_sid$get(MemorySegment seg) {
        return (short)bio_dgram_sctp_sndinfo.snd_sid$VH.get(seg);
    }
    public static void snd_sid$set( MemorySegment seg, short x) {
        bio_dgram_sctp_sndinfo.snd_sid$VH.set(seg, x);
    }
    public static short snd_sid$get(MemorySegment seg, long index) {
        return (short)bio_dgram_sctp_sndinfo.snd_sid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void snd_sid$set(MemorySegment seg, long index, short x) {
        bio_dgram_sctp_sndinfo.snd_sid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle snd_flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("snd_flags"));
    public static VarHandle snd_flags$VH() {
        return bio_dgram_sctp_sndinfo.snd_flags$VH;
    }
    public static short snd_flags$get(MemorySegment seg) {
        return (short)bio_dgram_sctp_sndinfo.snd_flags$VH.get(seg);
    }
    public static void snd_flags$set( MemorySegment seg, short x) {
        bio_dgram_sctp_sndinfo.snd_flags$VH.set(seg, x);
    }
    public static short snd_flags$get(MemorySegment seg, long index) {
        return (short)bio_dgram_sctp_sndinfo.snd_flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void snd_flags$set(MemorySegment seg, long index, short x) {
        bio_dgram_sctp_sndinfo.snd_flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle snd_ppid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("snd_ppid"));
    public static VarHandle snd_ppid$VH() {
        return bio_dgram_sctp_sndinfo.snd_ppid$VH;
    }
    public static int snd_ppid$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_sndinfo.snd_ppid$VH.get(seg);
    }
    public static void snd_ppid$set( MemorySegment seg, int x) {
        bio_dgram_sctp_sndinfo.snd_ppid$VH.set(seg, x);
    }
    public static int snd_ppid$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_sndinfo.snd_ppid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void snd_ppid$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_sndinfo.snd_ppid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle snd_context$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("snd_context"));
    public static VarHandle snd_context$VH() {
        return bio_dgram_sctp_sndinfo.snd_context$VH;
    }
    public static int snd_context$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_sndinfo.snd_context$VH.get(seg);
    }
    public static void snd_context$set( MemorySegment seg, int x) {
        bio_dgram_sctp_sndinfo.snd_context$VH.set(seg, x);
    }
    public static int snd_context$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_sndinfo.snd_context$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void snd_context$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_sndinfo.snd_context$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

