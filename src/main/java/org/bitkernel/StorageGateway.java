package org.bitkernel;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.IRSErasureCorrection;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.RSErasureCorrectionImpl;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;

@Slf4j
public class StorageGateway {
    private final static int SLICE_NUM = 4;
    private final static int CHECK_NUM = 2;
    private final static int TOTAL_BLOCK_NUM = SLICE_NUM + CHECK_NUM;
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

    public StorageGateway() {
        for (int i = 0; i < storages.length; i++) {
            storages[i] = new Storage();
        }
    }

    public void randomDestroyProvider() {
        int idx = new Random().nextInt(3);
        storages[idx].setWork(false);
        logger.debug("The {}th storage provider has been destroyed", idx);
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
        List<DataBlock> dataBlocks = generateDataBlocks(0, bytes);
        for (int i = 0; i < storages.length; i++) {
            if (!storages[i].isWork()) {
                logger.error("Current storage provider is not working, failed to store public key data blocks");
                return;
            }
            storages[i].putPubKeyBlock(groupTag, dataBlocks.get(i * 2));
            storages[i].putPubKeyBlock(groupTag, dataBlocks.get(i * 2 + 1));
        }
        logger.debug("Successfully store the public key");
    }

    private void storeSubPriKey(int keyId,
                                @NotNull String groupTag,
                                @NotNull String userName,
                                @NotNull byte[] subPriKey) {
        List<DataBlock> dataBlocks = generateDataBlocks(keyId, subPriKey);
        for (int i = 0; i < storages.length; i++) {
            if (!storages[i].isWork()) {
                logger.error("Current storage provider is not working, failed to store the sub-private key data blocks");
                return;
            }
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
        List<DataBlock> dataBlocks = slice(subKeyId, subPriKey, 4);
        byte[] combine = combine(dataBlocks, dataBlocks.size());
        IRSErasureCorrection rsProcessor = new RSErasureCorrectionImpl();
        byte[] dataWithChecksum = rsProcessor.encoder(combine, dataBlocks.get(0).getBytes().length, 4, 2);
        return convertToBlockList(dataWithChecksum, 6);
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
        return fullData;
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
        DataBlock[] dataBlocks = new DataBlock[6];
        for (int i = 0; i < storages.length; i++) {
            Storage storage = storages[i];
            if (!storage.isWork()) {
                logger.error("Current storage provider is not working, failed to get public key blocks");
                continue;
            }
            List<DataBlock> blocks = storage.getPubKeyBlock(groupTag);
            dataBlocks[i * 2] = blocks.get(0);
            dataBlocks[i * 2 + 1] = blocks.get(1);
        }
        byte[] bytes = recoverData(dataBlocks);
        return RSAUtil.getPublicKey(new String(bytes));
    }

    @NotNull
    public Pair<Integer, byte[]> getSubPriKey(@NotNull String userName,
                                              @NotNull String groupTag) {
        DataBlock[] dataBlocks = new DataBlock[6];
        for (int i = 0; i < storages.length; i++) {
            Storage storage = storages[i];
            if (!storage.isWork()) {
                logger.error("Current storage provider is not working, failed to get the sub-private key blocks");
                continue;
            }
            List<DataBlock> blocks = storage.getPriKeyDataBlocks(groupTag, userName);
            dataBlocks[i * 2] = blocks.get(0);
            dataBlocks[i * 2 + 1] = blocks.get(1);
        }
        int belongKeyId = Arrays.stream(dataBlocks).filter(Objects::nonNull)
                .findFirst().get().getBelongKeyId();
        return new Pair<>(belongKeyId, recoverData(dataBlocks));
    }

    /**
     * Recover data through Reel Solomon, it can guarantee service
     * even when a storage provider is no longer online.
     *
     * @param blocks a list of not less than four data blocks
     * @return origin data
     */
    @NotNull
    private byte[] recoverData(@NotNull DataBlock[] blocks) {
        int len = Arrays.stream(blocks).filter(Objects::nonNull)
                .map(d -> d.getBytes().length).reduce(0, Integer::max);
        byte[] dataBytesWithCheck = new byte[len * TOTAL_BLOCK_NUM];
        boolean[] eraserFlag = new boolean[TOTAL_BLOCK_NUM];
        Arrays.fill(eraserFlag, true);
        for (int i = 0; i < TOTAL_BLOCK_NUM; i++) {
            DataBlock block = blocks[i];
            if (block == null) {
                eraserFlag[i] = false;
                continue;
            }
            System.arraycopy(block.getBytes(), 0, dataBytesWithCheck, i * len, len);
        }

        IRSErasureCorrection rsProcessor = new RSErasureCorrectionImpl();
        int result = rsProcessor.decoder(dataBytesWithCheck, len, SLICE_NUM, CHECK_NUM, eraserFlag);
        if (result == 0) {
            logger.debug("Data recover success");
        } else {
            logger.error("Data recover failed");
        }

        List<DataBlock> dataBlocks = convertToBlockList(dataBytesWithCheck, 6);
        // remove check data blocks
        dataBlocks.remove(dataBlocks.size() - 1);
        dataBlocks.remove(dataBlocks.size() - 1);
        return parse(dataBlocks);
    }

    /**
     * Slice data into a list of data block
     */
    @NotNull
    private List<DataBlock> slice(int id, @NotNull byte[] bytes, int num) {
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

    /**
     * parsing out origin data based on data blocks
     */
    @NotNull
    private byte[] parse(@NotNull List<DataBlock> dataBlocks) {
        int validNum = dataBlocks.stream().map(DataBlock::getValByteNum)
                .reduce(0, Integer::sum);
        byte[] validBytes = new byte[validNum];
        int pos = 0;
        for (DataBlock dataBlock : dataBlocks) {
            byte[] dataBlockBytes = dataBlock.getValidBytes();
            System.arraycopy(dataBlockBytes, 0, validBytes,
                    pos, dataBlockBytes.length);
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
    @Setter
    @Getter
    private boolean isWork = true;

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
