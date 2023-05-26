package org.bitkernel;

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
    @Getter
    private final Map<String, Map<String, byte[]>> userSubPriKeyMap = new LinkedHashMap<>();
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
        List<byte[]> subPriKey = getPriKeySlicing(rsAKeyPair.getPrivateKey(), group.length);
        for (int i = 0; i < subPriKey.size(); i++) {
            String userName = group[i].getName();
            userSubPriKeyMap.putIfAbsent(userName, new LinkedHashMap<>());
            userSubPriKeyMap.get(userName).put(groupTag, subPriKey.get(i));
            storeSubPriKey(i, userName, groupTag, subPriKey.get(i));
        }
    }

    private void storeSubPriKey(int keyId,
                                @NotNull String userName,
                                @NotNull String groupTag,
                                @NotNull byte[] subPriKey) {
        int oneBlock = subPriKey.length / 4;
        byte[] checkBytes = new byte[oneBlock * 2];
        byte[] fullDataWithCheckData = new byte[subPriKey.length + checkBytes.length];
        System.arraycopy(subPriKey, 0, fullDataWithCheckData, 0, subPriKey.length);
        fullDataWithCheckData = Util.RSEncode(fullDataWithCheckData, checkBytes.length);
        System.arraycopy(fullDataWithCheckData, subPriKey.length, checkBytes, 0, checkBytes.length);

        List<DataBlock> dataBlocks = slice(keyId, subPriKey, 4);
        dataBlocks.addAll(slice(keyId, 4, checkBytes, 2));

        for (int i = 0; i < storages.length; i++) {
            storages[i].putPriKeyBlock(userName, groupTag, dataBlocks.get(i * 2));
            storages[i].putPriKeyBlock(userName, groupTag, dataBlocks.get(i * 2 + 1));
        }
    }

    @NotNull
    private List<byte[]> getPriKeySlicing(@NotNull PrivateKey priKey,
                                          @NotNull int num) {
        String priKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(priKey);
        byte[] bytes = priKeyEncodedBase64.getBytes();
        int subLen = (int) Math.ceil(bytes.length * 1.0 / num);
        List<byte[]> slices = new ArrayList<>();

        int pos = 0;
        while (pos < bytes.length) {
            int remain = bytes.length - pos;
            byte[] subBytes = new byte[Math.min(subLen, remain)];
            System.arraycopy(bytes, pos, subBytes, 0, subBytes.length);
            pos += subBytes.length;
            slices.add(subBytes);
        }

        return slices;
    }

    @NotNull
    public byte[] getSubPriKey(@NotNull String userName,
                               @NotNull String groupTag) {
        List<DataBlock> subPriBlocks = new ArrayList<>();
        for (Storage storage: this.storages) {
            List<DataBlock> blocks = storage.getPriKeyDataBlocks(userName, groupTag);
            subPriBlocks.addAll(blocks);
        }
        byte[] combine = combine(subPriBlocks, 6);
        int errorCorrectionSymbols = subPriBlocks.get(0).getBytes().length * 2;
        combine = Util.RSDecode(combine, errorCorrectionSymbols);
        List<DataBlock> dataBlocks = convertToBlockList(combine, 6);
        dataBlocks.remove(dataBlocks.size() - 1);
        dataBlocks.remove(dataBlocks.size() - 1);
        return parse(dataBlocks);
    }

    @NotNull
    private List<DataBlock> slice(int keyId, @NotNull byte[] bytes, int num) {
        return slice(keyId, 0, bytes, num);
    }

    @NotNull
    private List<DataBlock> slice(int keyId, int startBlockId, @NotNull byte[] bytes, int num) {
        int addByteNum = num - bytes.length % num;
        byte[] byteFormatted = new byte[addByteNum + bytes.length];
        System.arraycopy(bytes, 0, byteFormatted, 0, bytes.length);

        int subBlockSize = byteFormatted.length / num;
        List<DataBlock> dataBlocks = new ArrayList<>();

        int pos = 0;
        int blockId = startBlockId;
        while (pos < bytes.length) {
            int remainByte = bytes.length - pos;
            int valByteNum = Math.min(subBlockSize, remainByte);
            byte[] block = new byte[subBlockSize + DataBlock.FLAG_BYTE_LEN];
            block[0] = (byte) keyId;
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
        dataBlocks.sort(Comparator.comparing(DataBlock::getBlockId));
        for (DataBlock dataBlock: dataBlocks) {
            System.arraycopy(dataBlock.getBytes(), 0,
                    fullData, dataBlock.getBlockId() * totalLen, totalLen);
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
        List<DataBlock> slices = gateway.slice(0, bytes, 3);
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
    public static final int FLAG_BYTE_LEN = 4;
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
