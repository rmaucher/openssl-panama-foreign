// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class bio_dgram_sctp_rcvinfo {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_SHORT.withName("rcv_sid"),
        JAVA_SHORT.withName("rcv_ssn"),
        JAVA_SHORT.withName("rcv_flags"),
        MemoryLayout.paddingLayout(16),
        JAVA_INT.withName("rcv_ppid"),
        JAVA_INT.withName("rcv_tsn"),
        JAVA_INT.withName("rcv_cumtsn"),
        JAVA_INT.withName("rcv_context")
    ).withName("bio_dgram_sctp_rcvinfo");
    public static MemoryLayout $LAYOUT() {
        return bio_dgram_sctp_rcvinfo.$struct$LAYOUT;
    }
    static final VarHandle rcv_sid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_sid"));
    public static VarHandle rcv_sid$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_sid$VH;
    }
    public static short rcv_sid$get(MemorySegment seg) {
        return (short)bio_dgram_sctp_rcvinfo.rcv_sid$VH.get(seg);
    }
    public static void rcv_sid$set( MemorySegment seg, short x) {
        bio_dgram_sctp_rcvinfo.rcv_sid$VH.set(seg, x);
    }
    public static short rcv_sid$get(MemorySegment seg, long index) {
        return (short)bio_dgram_sctp_rcvinfo.rcv_sid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_sid$set(MemorySegment seg, long index, short x) {
        bio_dgram_sctp_rcvinfo.rcv_sid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rcv_ssn$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_ssn"));
    public static VarHandle rcv_ssn$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_ssn$VH;
    }
    public static short rcv_ssn$get(MemorySegment seg) {
        return (short)bio_dgram_sctp_rcvinfo.rcv_ssn$VH.get(seg);
    }
    public static void rcv_ssn$set( MemorySegment seg, short x) {
        bio_dgram_sctp_rcvinfo.rcv_ssn$VH.set(seg, x);
    }
    public static short rcv_ssn$get(MemorySegment seg, long index) {
        return (short)bio_dgram_sctp_rcvinfo.rcv_ssn$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_ssn$set(MemorySegment seg, long index, short x) {
        bio_dgram_sctp_rcvinfo.rcv_ssn$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rcv_flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_flags"));
    public static VarHandle rcv_flags$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_flags$VH;
    }
    public static short rcv_flags$get(MemorySegment seg) {
        return (short)bio_dgram_sctp_rcvinfo.rcv_flags$VH.get(seg);
    }
    public static void rcv_flags$set( MemorySegment seg, short x) {
        bio_dgram_sctp_rcvinfo.rcv_flags$VH.set(seg, x);
    }
    public static short rcv_flags$get(MemorySegment seg, long index) {
        return (short)bio_dgram_sctp_rcvinfo.rcv_flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_flags$set(MemorySegment seg, long index, short x) {
        bio_dgram_sctp_rcvinfo.rcv_flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rcv_ppid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_ppid"));
    public static VarHandle rcv_ppid$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_ppid$VH;
    }
    public static int rcv_ppid$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_ppid$VH.get(seg);
    }
    public static void rcv_ppid$set( MemorySegment seg, int x) {
        bio_dgram_sctp_rcvinfo.rcv_ppid$VH.set(seg, x);
    }
    public static int rcv_ppid$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_ppid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_ppid$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_rcvinfo.rcv_ppid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rcv_tsn$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_tsn"));
    public static VarHandle rcv_tsn$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_tsn$VH;
    }
    public static int rcv_tsn$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_tsn$VH.get(seg);
    }
    public static void rcv_tsn$set( MemorySegment seg, int x) {
        bio_dgram_sctp_rcvinfo.rcv_tsn$VH.set(seg, x);
    }
    public static int rcv_tsn$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_tsn$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_tsn$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_rcvinfo.rcv_tsn$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rcv_cumtsn$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_cumtsn"));
    public static VarHandle rcv_cumtsn$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_cumtsn$VH;
    }
    public static int rcv_cumtsn$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_cumtsn$VH.get(seg);
    }
    public static void rcv_cumtsn$set( MemorySegment seg, int x) {
        bio_dgram_sctp_rcvinfo.rcv_cumtsn$VH.set(seg, x);
    }
    public static int rcv_cumtsn$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_cumtsn$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_cumtsn$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_rcvinfo.rcv_cumtsn$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle rcv_context$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("rcv_context"));
    public static VarHandle rcv_context$VH() {
        return bio_dgram_sctp_rcvinfo.rcv_context$VH;
    }
    public static int rcv_context$get(MemorySegment seg) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_context$VH.get(seg);
    }
    public static void rcv_context$set( MemorySegment seg, int x) {
        bio_dgram_sctp_rcvinfo.rcv_context$VH.set(seg, x);
    }
    public static int rcv_context$get(MemorySegment seg, long index) {
        return (int)bio_dgram_sctp_rcvinfo.rcv_context$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void rcv_context$set(MemorySegment seg, long index, int x) {
        bio_dgram_sctp_rcvinfo.rcv_context$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


