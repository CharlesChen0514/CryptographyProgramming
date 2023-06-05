package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.IRSErasureCorrection;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.RSErasureCorrectionImpl;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.common.CmdType;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class StorageGateway {
    private final static int SLICE_NUM = 4;
    private final static int CHECK_NUM = 2;
    private final static int TOTAL_BLOCK_NUM = SLICE_NUM + CHECK_NUM;
    /** Group uuid -> public key, is only used as check */
    @Getter
    private final Map<String, PublicKey> publicKeyMap = new LinkedHashMap<>();
    /** Group uuid -> private key, is only used as check */
    @Getter
    private final Map<String, PrivateKey> privateKeyMap = new LinkedHashMap<>();
    /** Group uuid -> user name -> sub private key, is only used as check */
    @Getter
    private final Map<String, Map<String, byte[]>> userSubPriKeyMap = new LinkedHashMap<>();
    private final Storage[] storages = new Storage[3];
    private final Udp udp;

    public StorageGateway() {
        for (int i = 0; i < storages.length; i++) {
            storages[i] = new Storage();
        }
        udp = new Udp(Config.getStorageGatewayPort());
    }

    public static void main(String[] args) {
        StorageGateway storageGateway = new StorageGateway();
        storageGateway.run();
    }

    public void run() {
        logger.debug("StorageGateway start success");
        while (true) {
            String fullCmdLine = udp.receiveString();
            response(fullCmdLine);
        }
    }

    private void response(@NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String name = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case STORE:
                store(msg);
                break;
            default:
        }
    }

    private void store(@NotNull String msg) {
        String[] split = msg.split(":");
        String substring = split[0].substring(1, split[0].length() - 1);
        List<String> member = Arrays.asList(substring.split(","));
        String uuid = split[1].trim();
        PublicKey publicKey = RSAUtil.getPublicKey(split[2].trim());
        PrivateKey privateKey = RSAUtil.getPrivateKey(split[3].trim());
        store(member, uuid, new RSAKeyPair(publicKey, privateKey));
    }

    public void randomDestroyProvider() {
        while (true) {
            int idx = new Random().nextInt(3);
            if (storages[idx].isWork()) {
                storages[idx].setWork(false);
                logger.debug("The {}th storage provider has been destroyed", idx);
                break;
            }
        }
    }

    /**
     * Judge the recovered RSA key is correct or not
     */
    public boolean checkRecover(@NotNull List<String> group,
                                @NotNull String groupTag,
                                @NotNull RSAKeyPair rsAKeyPair) {
        boolean flag = checkRecoverPriKey(group, groupTag, rsAKeyPair.getPrivateKey());
        if (flag) {
            flag = checkRecoverPubKey(groupTag, rsAKeyPair.getPublicKey());
        }
        return flag;
    }

    private boolean checkRecoverPriKey(@NotNull List<String> group,
                                       @NotNull String groupTag,
                                       @NotNull PrivateKey privateKey) {
        List<byte[]> subPriKeys = getPriKeySlicing(privateKey, group.size());
        List<Storage> workingStorages = getWorkingStorages();
        boolean res = true;

        for (int i = 0; i < group.size(); i++) {
            String userName = group.get(i).trim();
            List<DataBlock> remainBlocks = workingStorages.stream()
                    .map(s -> s.getPriKeyDataBlocks(groupTag, userName))
                    .flatMap(Collection::stream).collect(Collectors.toList());
            String sliceStr = new String(combine(remainBlocks));

            List<DataBlock> dataBlocks = generateDataBlocks(i, subPriKeys.get(i));
            String subKeyStr = new String(combine(dataBlocks));
            if (subKeyStr.contains(sliceStr)) {
                logger.debug("The {}'s sub-private key recover successfully", userName);
            } else {
                logger.error("The {}'s sub-private key recover failed", userName);
                res = false;
            }
        }
        return res;
    }

    private boolean checkRecoverPubKey(@NotNull String groupTag,
                                       @NotNull PublicKey pubKey) {
        // get the remaining data block string
        List<Storage> workingStorages = getWorkingStorages();
        List<DataBlock> remainBlocks = workingStorages.stream().map(s -> s.getPubKeyBlock(groupTag))
                .flatMap(Collection::stream).collect(Collectors.toList());
        String sliceStr = new String(combine(remainBlocks));

        // get the all data blocks string combination of public key
        byte[] bytes = RSAUtil.getKeyEncodedBase64(pubKey).getBytes();
        List<DataBlock> dataBlocks = generateDataBlocks(0, bytes);
        String pubKeyStr = new String(combine(dataBlocks));

        // judge contains or not
        if (pubKeyStr.contains(sliceStr)) {
            logger.debug("The public key recover successfully");
            return true;
        } else {
            logger.error("The public key recover failed");
            return false;
        }
    }

    /**
     * store the public key and private key
     */
    public void store(@NotNull List<String> group,
                      @NotNull String groupUuid,
                      @NotNull RSAKeyPair rsAKeyPair) {
        // use as a check
        publicKeyMap.put(groupUuid, rsAKeyPair.getPublicKey());
        privateKeyMap.put(groupUuid, rsAKeyPair.getPrivateKey());

        storePriKey(group, groupUuid, rsAKeyPair.getPrivateKey());
        storePubKey(groupUuid, rsAKeyPair.getPublicKey());
    }

    private void storePriKey(@NotNull List<String> group,
                             @NotNull String groupTag,
                             @NotNull PrivateKey privateKey) {
        List<byte[]> subPriKey = getPriKeySlicing(privateKey, group.size());
        for (int i = 0; i < subPriKey.size(); i++) {
            String userName = group.get(i).trim();
            // use as a check
            userSubPriKeyMap.putIfAbsent(groupTag, new LinkedHashMap<>());
            userSubPriKeyMap.get(groupTag).put(userName, subPriKey.get(i));
            // actual storage action
            storeSubPriKey(i, groupTag, userName, subPriKey.get(i));
        }
    }

    private void storePubKey(@NotNull String groupTag,
                            @NotNull PublicKey pubKey) {
        String pubKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(pubKey);
        byte[] bytes = pubKeyEncodedBase64.getBytes();
        List<DataBlock> dataBlocks = generateDataBlocks(0, bytes);
        storePubKeyBlock(groupTag, dataBlocks);
        logger.debug("Successfully store the public key");
    }

    private void storeSubPriKey(int keyId,
                                @NotNull String groupTag,
                                @NotNull String userName,
                                @NotNull byte[] subPriKey) {
        List<DataBlock> dataBlocks = generateDataBlocks(keyId, subPriKey);
        storePriKeyBlock(groupTag, userName, dataBlocks);
        logger.debug("\n[{}]'s sub-private key is {}", userName, new String(subPriKey));
    }

    private void storePriKeyBlock(@NotNull String groupTag, @NotNull String userName,
                                  @NotNull List<DataBlock> dataBlocks) {
        List<Storage> workingStorages = getWorkingStorages();
        int perNum = dataBlocks.size() / workingStorages.size();
        for (int i = 0; i < workingStorages.size(); i++) {
            Storage storage = workingStorages.get(i);
            for (int j = 0; j < perNum; j++) {
                storage.putPriKeyBlock(groupTag, userName, dataBlocks.get(i * perNum + j));
            }
        }
    }

    private void storePubKeyBlock(@NotNull String groupTag, @NotNull List<DataBlock> dataBlocks) {
        List<Storage> workingStorages = getWorkingStorages();
        int perNum = dataBlocks.size() / workingStorages.size();
        for (int i = 0; i < workingStorages.size(); i++) {
            Storage storage = workingStorages.get(i);
            for (int j = 0; j < perNum; j++) {
                storage.putPubKeyBlock(groupTag, dataBlocks.get(i * perNum + j));
            }
        }
    }

    @NotNull
    private List<Storage> getWorkingStorages() {
        return Arrays.stream(storages).filter(Storage::isWork)
                .collect(Collectors.toList());
    }

    /**
     * Generate six data block include four from sub-key and two from check data
     * @param subKeyId serial number of sub-key
     * @return a list include six data block
     */
    @NotNull
    private List<DataBlock> generateDataBlocks(int subKeyId, @NotNull byte[] subPriKey) {
        List<DataBlock> dataBlocks = slice(subKeyId, subPriKey, 4);
        byte[] combine = combine(dataBlocks);
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

    /**
     * @param dataBlocks data block list
     * @return combination of data in data block list
     */
    @NotNull
    private byte[] combine(@NotNull List<DataBlock> dataBlocks) {
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
        DataBlock[] dataBlocks = new DataBlock[TOTAL_BLOCK_NUM];
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
        byte[] bytes = reedSolomonCheck(dataBlocks);
        return RSAUtil.getPublicKey(new String(bytes));
    }

    @NotNull
    public Pair<Integer, byte[]> getSubPriKey(@NotNull String userName,
                                              @NotNull String groupTag) {
        DataBlock[] dataBlocks = new DataBlock[TOTAL_BLOCK_NUM];
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
        return new Pair<>(belongKeyId, reedSolomonCheck(dataBlocks));
    }

    /**
     * Recover data through Reel Solomon, it can guarantee service
     * even when a storage provider is no longer online.
     *
     * @param blocks an array of data blocks of length {@link #TOTAL_BLOCK_NUM}
     * @return origin data
     */
    @NotNull
    private byte[] reedSolomonCheck(@NotNull DataBlock[] blocks) {
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

        // ensure the services can guarantee even a storage provider is broken
        IRSErasureCorrection rsProcessor = new RSErasureCorrectionImpl();
        int code = rsProcessor.decoder(dataBytesWithCheck, len, SLICE_NUM, CHECK_NUM, eraserFlag);
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
}
