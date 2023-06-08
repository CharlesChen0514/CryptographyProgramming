package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.IRSErasureCorrection;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.RSErasureCorrectionImpl;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

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

    @NotNull
    public static List<DataBlock> convertToBlockList(@NotNull byte[] bytes, int num) {
        int blockSize = bytes.length / num;
        List<DataBlock> dataBlocks = new ArrayList<>();
        for (int i = 0; i < num; i++) {
            byte[] block = new byte[blockSize];
            System.arraycopy(bytes, i * blockSize, block, 0, blockSize);
            dataBlocks.add(new DataBlock(block));
        }
        return dataBlocks;
    }

    /**
     * Generate six data block include four from sub-key and two from check data
     * @param subKeyId serial number of sub-key
     * @return a list include six data block
     */
    @NotNull
    public static List<DataBlock> generateDataBlocks(int subKeyId, @NotNull byte[] subPriKey) {
        List<DataBlock> dataBlocks = slice(subKeyId, subPriKey, 4);
        byte[] combine = combine(dataBlocks);
        IRSErasureCorrection rsProcessor = new RSErasureCorrectionImpl();
        byte[] dataWithChecksum = rsProcessor.encoder(combine, dataBlocks.get(0).getBytes().length, 4, 2);
        return DataBlock.convertToBlockList(dataWithChecksum, 6);
    }

    /**
     * @param dataBlocks data block list
     * @return combination of data in data block list
     */
    @NotNull
    public static byte[] combine(@NotNull List<DataBlock> dataBlocks) {
        int totalLen = dataBlocks.get(0).getBytes().length;
        byte[] fullData = new byte[totalLen * dataBlocks.size()];
        for (int i = 0; i < dataBlocks.size(); i++) {
            DataBlock dataBlock = dataBlocks.get(i);
            System.arraycopy(dataBlock.getBytes(), 0,
                    fullData, i * totalLen, totalLen);
        }
        return fullData;
    }

    /**
     * Slice data into a list of data block
     */
    @NotNull
    private static List<DataBlock> slice(int id, @NotNull byte[] bytes, int num) {
        // standardized data so that it can be divided by {num}
        int addByteNum = bytes.length % num == 0 ? 0 : num - bytes.length % num;
        byte[] byteFormatted = new byte[addByteNum + bytes.length];
        System.arraycopy(bytes, 0, byteFormatted, 0, bytes.length);

        int subBlockSize = byteFormatted.length / num;
        List<DataBlock> dataBlocks = new ArrayList<>();

        int pos = 0;
        int blockId = 0;
        while (pos < bytes.length) {
            int remainByte = bytes.length - pos;
            int valByteNum = Math.min(subBlockSize, remainByte);
            byte[] block = new byte[subBlockSize + DataBlock.FLAG_BYTE_LEN];
            // The first six bytes are fixed flag
            block[0] = (byte) id;
            block[1] = (byte) blockId;
            block[2] = (byte) (valByteNum >> 8);
            block[3] = (byte) valByteNum;
            System.arraycopy(byteFormatted, pos, block, DataBlock.FLAG_BYTE_LEN, valByteNum);
            DataBlock dataBlock = new DataBlock(block);
            dataBlocks.add(dataBlock);
            pos += valByteNum;
            blockId++;
        }

        return dataBlocks;
    }
}