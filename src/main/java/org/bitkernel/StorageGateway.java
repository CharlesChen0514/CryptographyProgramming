package org.bitkernel;

import com.google.zxing.common.reedsolomon.GenericGF;
import com.google.zxing.common.reedsolomon.ReedSolomonDecoder;
import com.google.zxing.common.reedsolomon.ReedSolomonEncoder;
import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;

@Slf4j
public class StorageGateway {
    private final static int REDUNDANCIES_SIZE = 2;
    private final static int DATA_BLOCK_NUM_PER_KEY = 4;
    private final GenericGF gf = GenericGF.AZTEC_DATA_8;
    private final ReedSolomonEncoder encoder = new ReedSolomonEncoder(gf);
    private final ReedSolomonDecoder decoder = new ReedSolomonDecoder(gf);
    /**
     * Group tag -> public key
     */
    private final Map<String, PublicKey> publicKeyMap = new LinkedHashMap<>();
    /**
     * Group tag -> private key
     */
    private final Map<String, PrivateKey> privateKeyMap = new LinkedHashMap<>();
    /**
     * User name -> Group tag -> sub private key
     */
    private final Map<String, Map<String, DataBlock>> userSubPriKeyMap = new LinkedHashMap<>();
    private final Storage[] storages = new Storage[3];

    public StorageGateway() {
        for (int i = 0; i < storages.length; i++) {
            storages[i] = new Storage();
        }
    }

    public void store(@NotNull User[] group,
                      @NotNull String groupTag,
                      @NotNull RSAKeyPair rsAKeyPair) {
        publicKeyMap.put(groupTag, rsAKeyPair.getPublicKey());
        privateKeyMap.put(groupTag, rsAKeyPair.getPrivateKey());
        List<DataBlock> subPriKey = priKeySlicing(rsAKeyPair.getPrivateKey(), group.length);
        for (int i = 0; i < subPriKey.size(); i++) {
            String userName = group[i].getName();
            userSubPriKeyMap.putIfAbsent(userName, new LinkedHashMap<>());
            userSubPriKeyMap.get(userName).put(groupTag, subPriKey.get(i));
            storeSubPriKey(userName, groupTag, subPriKey.get(i));
        }
    }

    private void storeSubPriKey(@NotNull String userName,
                                @NotNull String groupTag,
                                @NotNull DataBlock subPriKey) {
        List<DataBlock> dataBlocks = slice(subPriKey.getValidBytes(), 4);
        byte[] fullData = combine(dataBlocks, dataBlocks.size());
        int oneBlock = fullData.length / 4;
        byte[] fullDataWithCheckData = new byte[oneBlock * 6];
        System.arraycopy(fullData, 0, fullDataWithCheckData, 0, fullData.length);
        int errorCorrectionSymbols = oneBlock * 2;
        Util.RSEncode(fullDataWithCheckData, errorCorrectionSymbols);

        List<DataBlock> dataBlockWithCheckBlock = slice(fullData, 6);
        for (int i = 0; i < storages.length; i++) {
            storages[i].putPriKeyBlock(userName, groupTag, dataBlockWithCheckBlock.get(i * 2));
            storages[i].putPriKeyBlock(userName, groupTag, dataBlockWithCheckBlock.get(i * 2 + 1));
        }
    }

    @NotNull
    private List<DataBlock> priKeySlicing(@NotNull PrivateKey priKey,
                                          @NotNull int num) {
        String priKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(priKey);
        byte[] bytes = priKeyEncodedBase64.getBytes();
        return slice(bytes, num);
    }

    @NotNull
    private List<DataBlock> slice(@NotNull byte[] bytes, int num) {
        int addByteNum = num - bytes.length % num;
        byte[] byteFormatted = new byte[addByteNum + bytes.length];
        System.arraycopy(bytes, 0, byteFormatted, 0, bytes.length);

        int subBlockSize = byteFormatted.length / num;
        List<DataBlock> dataBlocks = new ArrayList<>();

        int pos = 0;
        int k = 0;
        while (pos < bytes.length) {
            int remainByte = bytes.length - pos;
            int valByteNum = Math.min(subBlockSize, remainByte);
            byte[] block = new byte[subBlockSize + 3];
            block[0] = (byte) k;
            block[1] = (byte) (valByteNum >> 8);
            block[2] = (byte) valByteNum;
            System.arraycopy(byteFormatted, pos, block, 3, valByteNum);
            DataBlock dataBlock = new DataBlock(block);
            dataBlocks.add(dataBlock);
            pos += valByteNum;
            k++;
        }

        return dataBlocks;
    }

    @NotNull
    private List<DataBlock> convertToBlockList(@NotNull byte[] bytes, int num) {
        int blockSize = bytes.length / num;
        List<DataBlock> dataBlocks = new ArrayList<>();
        for (int i = 0; i < num; i++) {
            byte[] block = new byte[blockSize];
            System.arraycopy(bytes, i * blockSize, block, 0, blockSize);
            dataBlocks.add(new DataBlock(block));
        }
        return dataBlocks;
    }

    @NotNull
    private byte[] combine(@NotNull List<DataBlock> dataBlocks, int num) {
        int totalLen = dataBlocks.get(0).getBytes().length;
        byte[] fullData = new byte[totalLen * num];
        dataBlocks.sort(Comparator.comparing(DataBlock::getK));
        for (DataBlock dataBlock: dataBlocks) {
            System.arraycopy(dataBlock.getBytes(), 0,
                    fullData, dataBlock.getK() * totalLen, totalLen);
        }
        // 这里做数据恢复，保证后面的数据正确
        return fullData;
    }

    @NotNull
    private byte[] parse(@NotNull List<DataBlock> dataBlocks) {
        int validByteNum = dataBlocks.stream().map(DataBlock::getValByteNum)
                .reduce(0, Integer::sum);
        byte[] validBytes = new byte[validByteNum];
        int pos = 0;
        for (DataBlock dataBlock: dataBlocks) {
            byte[] dataBlockBytes = dataBlock.getValidBytes();
            System.arraycopy(dataBlockBytes, 0, validBytes, pos, dataBlockBytes.length);
            pos += dataBlockBytes.length;
        }
        return validBytes;
    }

    public static void main(String[] args) {
        byte[] bytes = new byte[100];
        new SecureRandom().nextBytes(bytes);
        StorageGateway gateway = new StorageGateway();
        List<DataBlock> slices = gateway.slice(bytes, 3);
        byte[] combine = gateway.combine(slices, 3);
        List<DataBlock> dataBlocks = gateway.convertToBlockList(combine, 3);
        byte[] newBytes = gateway.parse(dataBlocks);
        String str1 = new String(bytes);
        String str2 = new String(newBytes);
        if (str1.equals(str2)) {
            System.out.println("Combine success");
        }
    }
}

@AllArgsConstructor
class DataBlock {
    /** | K(1) | valid length(2) | data(-) | */
    @Getter
    private final byte[] bytes;

    public int getK() {
        return bytes[0];
    }

    public int getValByteNum() {
        ByteBuffer buf = ByteBuffer.allocate(2);
        buf.put(bytes[1]);
        buf.put(bytes[2]);
        buf.position(0);
        return buf.getShort();
    }

    @NotNull
    public byte[] getData() {
        byte[] data = new byte[bytes.length - 3];
        System.arraycopy(bytes, 3, data, 0, data.length);
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

@Slf4j
class Storage {
    /** User name -> group tag -> data block */
    private final Map<String, Map<String, List<DataBlock>>> priKeyDataBlockMap = new LinkedHashMap<>();
    /** Group tag -> data block */
    private final Map<String, DataBlock> pubKeyDataBlockMap = new LinkedHashMap<>();

    public void putPriKeyBlock(@NotNull String userName,
                               @NotNull String groupTag,
                               @NotNull DataBlock dataBlock) {
        priKeyDataBlockMap.putIfAbsent(userName, new LinkedHashMap<>());
        priKeyDataBlockMap.get(userName).putIfAbsent(groupTag, new ArrayList<>());
        priKeyDataBlockMap.get(userName).get(groupTag).add(dataBlock);
    }

    @NotNull
    public List<DataBlock> getPriKeyDataBlocks(@NotNull String userName,
                                               @NotNull String groupTag) {
        if (!priKeyDataBlockMap.containsKey(userName)) {
            logger.error("Username {} not found", userName);
            return new ArrayList<>();
        }
        if (!priKeyDataBlockMap.get(userName).containsKey(groupTag)) {
            logger.error("Group tag {} not found", groupTag);
            return new ArrayList<>();
        }
        return priKeyDataBlockMap.get(userName).get(groupTag);
    }

    public void putPubKeyBlock(@NotNull String groupTag,
                               @NotNull DataBlock dataBlock) {
        pubKeyDataBlockMap.put(groupTag, dataBlock);
    }
}
