package org.bitkernel;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
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
    /** Group tag -> public key, is only used as check */
    @Getter
    private final Map<String, PublicKey> publicKeyMap = new LinkedHashMap<>();
    /** Group tag -> private key, is only used as check */
    @Getter
    private final Map<String, PrivateKey> privateKeyMap = new LinkedHashMap<>();
    /** Group tag -> user name -> sub private key, is only used as check */
    @Getter
    private final Map<String, Map<String, byte[]>> userSubPriKeyMap = new LinkedHashMap<>();
    private final Storage[] storages = new Storage[3];
    /** Group tag -> user name -> sub-private key length */
    private final Map<String, Map<String, Integer>> subPriKeyLenMap = new LinkedHashMap<>();
    /** Group tag ->  public key length */
    private final Map<String, Integer> pubKeyLenMap = new LinkedHashMap<>();

    public StorageGateway() {
        for (int i = 0; i < storages.length; i++) {
            storages[i] = new Storage();
        }
    }

    /**
     * store the public key and private key
     */
    public void store(@NotNull User[] group,
                      @NotNull String groupTag,
                      @NotNull RSAKeyPair rsAKeyPair) {
        // use as a check
        publicKeyMap.put(groupTag, rsAKeyPair.getPublicKey());
        privateKeyMap.put(groupTag, rsAKeyPair.getPrivateKey());

        List<byte[]> subPriKey = getPriKeySlicing(rsAKeyPair.getPrivateKey(), group.length);
        for (int i = 0; i < subPriKey.size(); i++) {
            String userName = group[i].getName();
            // use as a check
            userSubPriKeyMap.putIfAbsent(groupTag, new LinkedHashMap<>());
            userSubPriKeyMap.get(groupTag).put(userName, subPriKey.get(i));
            // actual storage action
            storeSubPriKey(i, groupTag, userName, subPriKey.get(i));
        }
        storePubKey(groupTag, rsAKeyPair.getPublicKey());
    }

    public void storePubKey(@NotNull String groupTag,
                            @NotNull PublicKey pubKey) {
        String pubKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(pubKey);
        byte[] bytes = pubKeyEncodedBase64.getBytes();
        pubKeyLenMap.put(groupTag, bytes.length);
        List<DataBlock> dataBlocks = generateDataBlocks(0, bytes);
        for (int i = 0; i < storages.length; i++) {
            storages[i].putPubKeyBlock(groupTag, dataBlocks.get(i * 2));
            storages[i].putPubKeyBlock(groupTag, dataBlocks.get(i * 2 + 1));
        }
        logger.debug("Successfully store the public key");
    }

    private void storeSubPriKey(int keyId,
                                @NotNull String groupTag,
                                @NotNull String userName,
                                @NotNull byte[] subPriKey) {
        subPriKeyLenMap.putIfAbsent(groupTag, new LinkedHashMap<>());
        subPriKeyLenMap.get(groupTag).put(userName, subPriKey.length);

        List<DataBlock> dataBlocks = generateDataBlocks(keyId, subPriKey);
        for (int i = 0; i < storages.length; i++) {
            storages[i].putPriKeyBlock(groupTag, userName, dataBlocks.get(i * 2));
            storages[i].putPriKeyBlock(groupTag, userName, dataBlocks.get(i * 2 + 1));
        }
        logger.debug("\n[{}]'s sub-private key is {}", userName, new String(subPriKey));
    }

    /**
     * Generate six data block include four from sub-key and two from check data
     * @param subKeyId serial number of sub-key
     * @return a list include six data block
     */
    @NotNull
    private List<DataBlock> generateDataBlocks(int subKeyId, @NotNull byte[] subPriKey) {
        int oneBlock = (int) Math.ceil(subPriKey.length * 1.0 / 4);
        byte[] checkBytes = new byte[oneBlock * 2];
        byte[] fullDataWithCheckData = new byte[subPriKey.length + checkBytes.length];
        System.arraycopy(subPriKey, 0, fullDataWithCheckData, 0, subPriKey.length);
        fullDataWithCheckData = ReedSolomonUtil.encode(fullDataWithCheckData, checkBytes.length);
        System.arraycopy(fullDataWithCheckData, subPriKey.length, checkBytes, 0, checkBytes.length);

        List<DataBlock> dataBlocks = slice(subKeyId, subPriKey, 4);
        dataBlocks.addAll(slice(subKeyId, 4, checkBytes, 2));
        return dataBlocks;
    }

    /**
     * Split private key into sub-private keys
     * @param priKey private key
     * @param num split number
     * @return sub-private key list
     */
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
    public PublicKey getPubKey(@NotNull String groupTag) {
        List<DataBlock> dataBlocks = new ArrayList<>();
        for (Storage storage: storages) {
            dataBlocks.addAll(storage.getPubKeyBlock(groupTag));
        }
        byte[] bytes = recoverData(dataBlocks);
        return RSAUtil.getPublicKey(new String(bytes));
    }

    @NotNull
    public Pair<Integer, byte[]> getSubPriKey(@NotNull String userName,
                                              @NotNull String groupTag) {
        List<DataBlock> subPriBlocks = new ArrayList<>();
        for (Storage storage: this.storages) {
            List<DataBlock> blocks = storage.getPriKeyDataBlocks(groupTag, userName);
            subPriBlocks.addAll(blocks);
        }
        int belongKeyId = subPriBlocks.get(0).getBelongKeyId();
        return new Pair<>(belongKeyId, recoverData(subPriBlocks));
    }

    @NotNull
    private byte[] recoverData(@NotNull List<DataBlock> blocks) {
        byte[] dataBytesWithCheck = parse(blocks);
        int errorCorrectionSymbols = blocks.get(0).getDataCapacity() * 2;
        dataBytesWithCheck = ReedSolomonUtil.decode(dataBytesWithCheck, errorCorrectionSymbols);
        byte[] bytes = new byte[dataBytesWithCheck.length - errorCorrectionSymbols];
        System.arraycopy(dataBytesWithCheck, 0, bytes, 0, bytes.length);
        return bytes;
    }

    /**
     * Slice data into a list of data block
     */
    @NotNull
    private List<DataBlock> slice(int id, @NotNull byte[] bytes, int num) {
        return slice(id, 0, bytes, num);
    }

    /**
     * @param startBlockId the id of the starting data block
     */
    @NotNull
    private List<DataBlock> slice(int keyId, int startBlockId,
                                  @NotNull byte[] bytes, int num) {
        // standardized data so that it can be divided by {num}
        int addByteNum = bytes.length % num == 0 ? 0 : num - bytes.length % num;
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
            // The first four bytes are fixed flag
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
        byte[] newBytes = gateway.parse(slices);
        String str1 = new String(bytes);
        String str2 = new String(newBytes);
        if (str1.equals(str2)) {
            System.out.println("Combine success");
        }
    }
}

@AllArgsConstructor
class DataBlock {
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

@Slf4j
class Storage {
    /** Group tag -> user name -> data block */
    private final Map<String, Map<String, List<DataBlock>>> priKeyDataBlockMap = new LinkedHashMap<>();
    /** Group tag -> data block */
    private final Map<String, List<DataBlock>> pubKeyDataBlockMap = new LinkedHashMap<>();

    public void putPriKeyBlock(@NotNull String groupTag,
                               @NotNull String userName,
                               @NotNull DataBlock dataBlock) {
        priKeyDataBlockMap.putIfAbsent(groupTag, new LinkedHashMap<>());
        priKeyDataBlockMap.get(groupTag).putIfAbsent(userName, new ArrayList<>());
        priKeyDataBlockMap.get(groupTag).get(userName).add(dataBlock);
    }

    @NotNull
    public List<DataBlock> getPriKeyDataBlocks(@NotNull String groupTag,
                                               @NotNull String userName) {
        if (!priKeyDataBlockMap.containsKey(groupTag)) {
            logger.error("Group tag {} not found", groupTag);
            return new ArrayList<>();
        }
        if (!priKeyDataBlockMap.get(groupTag).containsKey(userName)) {
            logger.error("User name {} not found", userName);
            return new ArrayList<>();
        }
        return priKeyDataBlockMap.get(groupTag).get(userName);
    }

    public void putPubKeyBlock(@NotNull String groupTag,
                               @NotNull DataBlock dataBlock) {
        pubKeyDataBlockMap.putIfAbsent(groupTag, new ArrayList<>());
        pubKeyDataBlockMap.get(groupTag).add(dataBlock);
    }

    @NotNull
    public List<DataBlock> getPubKeyBlock(@NotNull String groupTag) {
        if (!pubKeyDataBlockMap.containsKey(groupTag)) {
            logger.error("Group tag {} not found", groupTag);
            return new ArrayList<>();
        }
        return pubKeyDataBlockMap.get(groupTag);
    }
}
