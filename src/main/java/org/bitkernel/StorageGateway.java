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
        List<DataBlock> dataBlocks = slice(subPriKey.getValidDataBytes(), 4);
        int[] fullData = combine(dataBlocks, dataBlocks.size());
        int oneBlock = fullData.length / 4;
        int[] fullDataWithCheckData = new int[oneBlock * 6];
        System.arraycopy(fullData, 0, fullDataWithCheckData, 0, fullData.length);
        int errorCorrectionSymbols = oneBlock * 2;
        encoder.encode(fullDataWithCheckData, errorCorrectionSymbols);

        List<DataBlock> dataBlockWithCheckBlock = slice(Util.intArrayToByteArray(fullData), 6);
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

        int[] intArray = Util.byteArrayToIntArray(byteFormatted);
        int subBlockSize = intArray.length / num;
        List<DataBlock> dataBlocks = new ArrayList<>();

        int pos = 0;
        int k = 0;
        while (pos < bytes.length) {
            int remainByte = bytes.length - pos;
            int valByteNum = Math.min(subBlockSize, remainByte);
            int[] block = new int[subBlockSize + 3];
            block[0] = k;
            block[1] = valByteNum;
            block[2] = subBlockSize;
            System.arraycopy(intArray, pos, block, 3, valByteNum);
            DataBlock dataBlock = new DataBlock(block);
            dataBlocks.add(dataBlock);
            pos += valByteNum;
            k++;
        }

        return dataBlocks;
    }

    @NotNull
    private int[] combine(@NotNull List<DataBlock> dataBlocks, int num) {
        int totalLen = dataBlocks.get(0).getBlock().length;
        int[] fullData = new int[totalLen * num];
        dataBlocks.sort(Comparator.comparing(DataBlock::getK));
        for (DataBlock dataBlock: dataBlocks) {
            System.arraycopy(dataBlock.getBlock(), 0,
                    fullData, dataBlock.getK() * totalLen, totalLen);
        }
        // 这里做数据恢复，保证后面的数据正确
        return fullData;
    }

    @NotNull
    private byte[] parse(@NotNull int[] fullData) {
        int validByteNum = 0;
        int c = 0;
        List<int[]> dataBlocks = new ArrayList<>();
        int pos = 0;
        while (pos < fullData.length) {
            validByteNum += fullData[pos + 1];
            int totalLen = fullData[pos + 2];
            c += totalLen;
            int[] data = new int[totalLen];
            System.arraycopy(fullData, pos + 3, data, 0, totalLen);
            pos += totalLen + 3;
            dataBlocks.add(data);
        }
        int[] fullDataMsg = new int[c];
        pos = 0;
        for (int[] d : dataBlocks) {
            System.arraycopy(d, 0, fullDataMsg, pos, d.length);
            pos += d.length;
        }
        byte[] bytes = Util.intArrayToByteArray(fullDataMsg);
        byte[] validBytes = new byte[validByteNum];
        System.arraycopy(bytes, 0, validBytes, 0, validByteNum);
        return validBytes;
    }

    public static void main(String[] args) {
        byte[] bytes = new byte[100];
        new SecureRandom().nextBytes(bytes);
        StorageGateway gateway = new StorageGateway();
        List<DataBlock> slices = gateway.slice(bytes, 3);
        int[] combine = gateway.combine(slices, 3);
        byte[] newBytes = gateway.parse(combine);
        String str1 = new String(bytes);
        String str2 = new String(newBytes);
        if (str1.equals(str2)) {
            System.out.println("Combine success");
        }
    }
}

@AllArgsConstructor
class DataBlock {
    /**
     * | start idx(2) | valid length(2) | total length(2) | data(-) |
     */
    @Getter
    private final int[] block;

    public int getK() {
        return block[0];
    }

    public int getValByteNum() {
        return block[1];
    }

    public int getTotalByteNum() {
        return block[2];
    }

    @NotNull
    public int[] getData() {
        int[] data = new int[block.length - 3];
        System.arraycopy(block, 3, data, 0, data.length);
        return data;
    }

    @NotNull
    public byte[] getValidDataBytes() {
        int[] data = getData();
        byte[] dataBytes = new byte[getValByteNum()];
        System.arraycopy(Util.intArrayToByteArray(data), 0, dataBytes, 0, getValByteNum());
        return dataBytes;
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