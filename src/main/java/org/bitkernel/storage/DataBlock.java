package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.nio.ByteBuffer;

@AllArgsConstructor
public class DataBlock {
    public static final int FLAG_BYTE_LEN = 1 + 1 + 2;
    /** | belongKeyId(1) | BlockId(1) | valid length(2) | data(-) | */
    @Getter
    private final byte[] bytes;

    public int getBelongKeyId() {
        return bytes[0];
    }

    public int getBlockId() {
        return bytes[1];
    }

    public int getValByteNum() {
        ByteBuffer buf = ByteBuffer.allocate(2);
        buf.put(bytes[2]);
        buf.put(bytes[3]);
        buf.position(0);
        return buf.getShort();
    }

    public int getDataCapacity() {
        return bytes.length - FLAG_BYTE_LEN;
    }

    @NotNull
    public byte[] getData() {
        byte[] data = new byte[bytes.length - FLAG_BYTE_LEN];
        System.arraycopy(bytes, FLAG_BYTE_LEN, data, 0, data.length);
        return data;
    }

    @NotNull
    public byte[] getValidBytes() {
        byte[] data = getData();
        byte[] validBytes = new byte[getValByteNum()];
        System.arraycopy(data, 0, validBytes, 0, getValByteNum());
        return validBytes;
    }
}