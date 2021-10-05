// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class pkcs7_issuer_and_serial_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("issuer"),
        ADDRESS.withName("serial")
    ).withName("pkcs7_issuer_and_serial_st");
    public static MemoryLayout $LAYOUT() {
        return pkcs7_issuer_and_serial_st.$struct$LAYOUT;
    }
    static final VarHandle issuer$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("issuer"));
    public static VarHandle issuer$VH() {
        return pkcs7_issuer_and_serial_st.issuer$VH;
    }
    public static MemoryAddress issuer$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_issuer_and_serial_st.issuer$VH.get(seg);
    }
    public static void issuer$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_issuer_and_serial_st.issuer$VH.set(seg, x);
    }
    public static MemoryAddress issuer$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_issuer_and_serial_st.issuer$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void issuer$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_issuer_and_serial_st.issuer$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle serial$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("serial"));
    public static VarHandle serial$VH() {
        return pkcs7_issuer_and_serial_st.serial$VH;
    }
    public static MemoryAddress serial$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_issuer_and_serial_st.serial$VH.get(seg);
    }
    public static void serial$set( MemorySegment seg, MemoryAddress x) {
        pkcs7_issuer_and_serial_st.serial$VH.set(seg, x);
    }
    public static MemoryAddress serial$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)pkcs7_issuer_and_serial_st.serial$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void serial$set(MemorySegment seg, long index, MemoryAddress x) {
        pkcs7_issuer_and_serial_st.serial$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


