package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.IRSErasureCorrection;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.RSErasureCorrectionImpl;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;

import java.net.SocketException;
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
    private final Udp udp;
    private final String sysName = "gate way";

    public StorageGateway() {
        udp = new Udp();
        try {
            udp.getSocket().setSoTimeout(100);
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Judge the recovered RSA key is correct or not
     */
    public boolean checkRecover(@NotNull List<String> group,
                                @NotNull String groupUuid,
                                @NotNull RSAKeyPair rsAKeyPair) {
        boolean flag = checkRecoverPriKey(group, groupUuid, rsAKeyPair.getPrivateKey());
        if (flag) {
            flag = checkRecoverPubKey(groupUuid, rsAKeyPair.getPublicKey());
        }
        return flag;
    }

    private boolean checkRecoverPriKey(@NotNull List<String> group,
                                       @NotNull String groupTag,
                                       @NotNull PrivateKey privateKey) {
        List<byte[]> subPriKeys = getPriKeySlicing(privateKey, group.size());
        List<Integer> workingStorageIdList = getWorkingStorageIdxs();
        boolean res = true;

        for (int i = 0; i < group.size(); i++) {
            String userName = group.get(i).trim();
            List<DataBlock> remainBlocks = workingStorageIdList.stream()
                    .map(id -> getPriKeyDataBlocks(id, groupTag, userName))
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

    private boolean checkRecoverPubKey(@NotNull String groupUuid,
                                       @NotNull PublicKey pubKey) {
        // get the remaining data block string
        List<Integer> workingStorageIdList = getWorkingStorageIdxs();
        List<DataBlock> remainBlocks = workingStorageIdList.stream().map(id -> getPubKeyBlocks(id, groupUuid))
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

    public void remove(@NotNull String groupUuid) {
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        String cmd = String.format("%s@%s@%s", sysName, CmdType.REMOVE.cmd, groupUuid);
        for (int idx : workingStorageIdxList) {
            udp.send(Config.getStorageIp(idx), Config.getStoragePort(idx), cmd);
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

    private void storePubKey(@NotNull String groupUuid,
                            @NotNull PublicKey pubKey) {
        String pubKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(pubKey);
        byte[] bytes = pubKeyEncodedBase64.getBytes();
        List<DataBlock> dataBlocks = generateDataBlocks(0, bytes);
        storePubKeyBlock(groupUuid, dataBlocks);
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
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        int perNum = dataBlocks.size() / workingStorageIdxList.size();
        for (int i = 0; i < workingStorageIdxList.size(); i++) {
            int storageIdx = workingStorageIdxList.get(i);
            for (int j = 0; j < perNum; j++) {
                int blockId = i * perNum + j;
                DataBlock dataBlock = dataBlocks.get(blockId);
                if (putPriKeyBlock(storageIdx, groupTag, userName, dataBlock)) {
                    logger.debug("Store the {}th pri key data block success, block length: {}",
                            blockId, dataBlock.getBytes().length);
                } else {
                    logger.error("Store the {}th pri key data block failed", blockId);
                }
            }
        }
    }

    private boolean putPriKeyBlock(int idx, @NotNull String groupUuid,
                                   @NotNull String userName, @NotNull DataBlock dataBlock) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s:%s:%s", sysName, CmdType.PUT_PRI_KEY_BLOCK.cmd,
                groupUuid, userName, Arrays.toString(dataBlock.getBytes()));
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return rsp.equals("TRUE");
    }

    private void storePubKeyBlock(@NotNull String groupUuid,
                                  @NotNull List<DataBlock> dataBlocks) {
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        int perNum = dataBlocks.size() / workingStorageIdxList.size();
        for (int i = 0; i < workingStorageIdxList.size(); i++) {
            int storageIdx = workingStorageIdxList.get(i);
            for (int j = 0; j < perNum; j++) {
                int blockId = i * perNum + j;
                DataBlock dataBlock = dataBlocks.get(blockId);
                if (putPubKeyBlock(storageIdx, groupUuid, dataBlock)) {
                    logger.debug("Store the {}th pub key data block success, block length: {}",
                            blockId, dataBlock.getBytes().length);
                } else {
                    logger.error("Store the {}th pub key data block failed", blockId);
                }
            }
        }
    }

    private boolean putPubKeyBlock(int idx, @NotNull String groupUuid,
                                   @NotNull DataBlock dataBlock) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s:%s",
                sysName, CmdType.PUT_PUB_KEY_BLOCK.cmd, groupUuid, Arrays.toString(dataBlock.getBytes()));
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return rsp.equals("TRUE");
    }

    @NotNull
    private List<Integer> getWorkingStorageIdxs() {
        List<Integer> idxs = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            String ip = Config.getStorageIp(i);
            int port = Config.getStoragePort(i);
            String msg = String.format("%s@%s@ ", sysName, CmdType.HEART_BEAT.cmd);
            udp.send(ip, port, msg);
            String rsp = udp.receiveString();
            if (rsp.equals("ALIVE")) {
                idxs.add(i);
            } else {
                logger.error("Storage{} is not working", i);
            }
        }
        return idxs;
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
    public PublicKey getPubKey(@NotNull String groupUuid) {
        DataBlock[] dataBlocks = new DataBlock[TOTAL_BLOCK_NUM];
        List<Integer> workingStorageIdList = getWorkingStorageIdxs();
        for (int idx : workingStorageIdList) {
            List<DataBlock> blocks = getPubKeyBlocks(idx, groupUuid);
            for (DataBlock block: blocks) {
                dataBlocks[block.getBlockId()] = block;
            }
        }
        byte[] bytes = reedSolomonCheck(dataBlocks);
        return RSAUtil.getPublicKey(new String(bytes));
    }

    @NotNull
    private List<DataBlock> getPubKeyBlocks(int idx, @NotNull String groupUuid) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s", sysName, CmdType.GET_PUB_KEY_BLOCKS.cmd, groupUuid);
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return convertToDataBlocks(rsp);
    }

    @NotNull
    public Pair<Integer, byte[]> getSubPriKey(@NotNull String groupUuid,
                                              @NotNull String userName) {
        DataBlock[] dataBlocks = new DataBlock[TOTAL_BLOCK_NUM];
        List<Integer> workingStorageIdList = getWorkingStorageIdxs();
        for (int idx : workingStorageIdList) {
            List<DataBlock> blocks = getPriKeyDataBlocks(idx, groupUuid, userName);
            for (DataBlock block : blocks) {
                dataBlocks[block.getBlockId()] = block;
            }
        }
        int belongKeyId = Arrays.stream(dataBlocks).filter(Objects::nonNull)
                .findFirst().get().getBelongKeyId();
        return new Pair<>(belongKeyId, reedSolomonCheck(dataBlocks));
    }

    @NotNull
    private List<DataBlock> getPriKeyDataBlocks(int idx, @NotNull String groupUuid,
                                                @NotNull String userName) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s:%s", sysName,
                CmdType.GET_PRI_KEY_BLOCKS.cmd, groupUuid, userName);
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return convertToDataBlocks(rsp);
    }

    @NotNull
    private static byte[] stringToByteArray(@NotNull String str) {
        String[] strArray = str.replaceAll("[\\[\\]\\s]", "").split(",");
        byte[] byteArray = new byte[strArray.length];
        for (int i = 0; i < strArray.length; i++) {
            byteArray[i] = Byte.parseByte(strArray[i]);
        }
        return byteArray;
    }

    @NotNull
    private static List<DataBlock> convertToDataBlocks(@NotNull String rsp) {
        String[] split = rsp.split(":");
        List<DataBlock> dataBlocks = new ArrayList<>();
        for (String blockStr : split) {
            byte[] bytes = stringToByteArray(blockStr);
            DataBlock block = new DataBlock(bytes);
            dataBlocks.add(block);
        }
        return dataBlocks;
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
