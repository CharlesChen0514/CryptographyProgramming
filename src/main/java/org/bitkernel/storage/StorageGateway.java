package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Util;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.IRSErasureCorrection;
import org.bitkernel.reedsolomon.robinliew.dealbytesinterface.RSErasureCorrectionImpl;
import org.bitkernel.cryptography.RSAUtil;

import java.net.SocketException;
import java.security.PublicKey;
import java.util.*;

@Slf4j
public class StorageGateway {
    private final static int SLICE_NUM = 4;
    private final static int CHECK_NUM = 2;
    private final static int TOTAL_BLOCK_NUM = SLICE_NUM + CHECK_NUM;
    private final Udp udp;
    private final String sysName = "gate way";

    public StorageGateway() {
        udp = new Udp();
        try {
            udp.getSocket().setSoTimeout(50);
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }

    public void removePubKey(@NotNull String pubHashKey) {
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        String cmd = String.format("%s@%s@%s", sysName, CmdType.REMOVE_PUB_KEY.cmd, pubHashKey);
        for (int idx : workingStorageIdxList) {
            udp.send(Config.getStorageIp(idx), Config.getStoragePort(idx), cmd);
        }
    }

    public void removeSubPriKey(@NotNull String priHashKey) {
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        String cmd = String.format("%s@%s@%s", sysName, CmdType.REMOVE_PRI_KEY.cmd, priHashKey);
        for (int idx : workingStorageIdxList) {
            udp.send(Config.getStorageIp(idx), Config.getStoragePort(idx), cmd);
        }
    }

    public boolean contains(@NotNull String hashKey) {
        return blockNum(hashKey) != 0;
    }

    public void storePriKeyBlock(@NotNull String hashKey,
                                 @NotNull List<DataBlock> dataBlocks) {
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        int perNum = dataBlocks.size() / workingStorageIdxList.size();
        for (int i = 0; i < workingStorageIdxList.size(); i++) {
            int storageIdx = workingStorageIdxList.get(i);
            for (int j = 0; j < perNum; j++) {
                int blockId = i * perNum + j;
                DataBlock dataBlock = dataBlocks.get(blockId);
                if (putPriKeyBlock(storageIdx, hashKey, dataBlock)) {
                    logger.debug("Store the {}th pri key data block success, block length: {}",
                            blockId, dataBlock.getBytes().length);
                } else {
                    logger.error("Store the {}th pri key data block failed", blockId);
                }
            }
        }
    }

    private boolean putPriKeyBlock(int idx, @NotNull String hashKey,
                                   @NotNull DataBlock dataBlock) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s:%s", sysName, CmdType.PUT_PRI_KEY_BLOCK.cmd,
                hashKey, Arrays.toString(dataBlock.getBytes()));
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return rsp.equals("TRUE");
    }

    public void storePubKeyBlock(@NotNull String hashKey,
                                  @NotNull List<DataBlock> dataBlocks) {
        List<Integer> workingStorageIdxList = getWorkingStorageIdxs();
        int perNum = dataBlocks.size() / workingStorageIdxList.size();
        for (int i = 0; i < workingStorageIdxList.size(); i++) {
            int storageIdx = workingStorageIdxList.get(i);
            for (int j = 0; j < perNum; j++) {
                int blockId = i * perNum + j;
                DataBlock dataBlock = dataBlocks.get(blockId);
                if (putPubKeyBlock(storageIdx, hashKey, dataBlock)) {
                    logger.debug("Store the {}th pub key data block success, block length: {}",
                            blockId, dataBlock.getBytes().length);
                } else {
                    logger.error("Store the {}th pub key data block failed", blockId);
                }
            }
        }
    }

    private boolean putPubKeyBlock(int idx, @NotNull String hashKey,
                                   @NotNull DataBlock dataBlock) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s:%s",
                sysName, CmdType.PUT_PUB_KEY_BLOCK.cmd, hashKey, Arrays.toString(dataBlock.getBytes()));
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

    public int blockNum(@NotNull String hashKey) {
        return getPubKeyBlocks(hashKey).size();
    }

    @NotNull
    public List<DataBlock> getPubKeyBlocks(@NotNull String hashKey) {
        List<Integer> workingStorageIdList = getWorkingStorageIdxs();
        List<DataBlock> res = new ArrayList<>();
        for (int idx : workingStorageIdList) {
            res.addAll(getPubKeyBlocks(idx, hashKey));
        }
        return res;
    }

    @NotNull
    public PublicKey getPubKey(@NotNull String hashKey) {
        DataBlock[] dataBlocks = new DataBlock[TOTAL_BLOCK_NUM];
        List<DataBlock> pubKeyBlocks = getPubKeyBlocks(hashKey);
        for (DataBlock block: pubKeyBlocks) {
            dataBlocks[block.getBlockId()] = block;
        }
        byte[] bytes = reedSolomonCheck(dataBlocks);
        return RSAUtil.getPublicKey(new String(bytes));
    }

    @NotNull
    private List<DataBlock> getPubKeyBlocks(int idx, @NotNull String hashKey) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s", sysName, CmdType.GET_PUB_KEY_BLOCKS.cmd, hashKey);
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return convertToDataBlocks(rsp);
    }

    @NotNull
    public List<DataBlock> getSubPriKeyBlocks(@NotNull String hashKey) {
        List<Integer> workingStorageIdList = getWorkingStorageIdxs();
        List<DataBlock> res = new ArrayList<>();
        for (int idx : workingStorageIdList) {
            List<DataBlock> blocks = getPriKeyDataBlocks(idx, hashKey);
            res.addAll(blocks);
        }
        return res;
    }

    @NotNull
    public Pair<Integer, byte[]> getSubPriKey(@NotNull String hashKey) {
        DataBlock[] dataBlocks = new DataBlock[TOTAL_BLOCK_NUM];
        List<DataBlock> subPriKeyBlocks = getSubPriKeyBlocks(hashKey);
        for (DataBlock block : subPriKeyBlocks) {
            dataBlocks[block.getBlockId()] = block;
        }
        int belongKeyId = Arrays.stream(dataBlocks).filter(Objects::nonNull)
                .findFirst().get().getBelongKeyId();
        return new Pair<>(belongKeyId, reedSolomonCheck(dataBlocks));
    }

    @NotNull
    private List<DataBlock> getPriKeyDataBlocks(int idx, @NotNull String hashKey) {
        String ip = Config.getStorageIp(idx);
        int port = Config.getStoragePort(idx);
        String cmd = String.format("%s@%s@%s", sysName,
                CmdType.GET_PRI_KEY_BLOCKS.cmd, hashKey);
        udp.send(ip, port, cmd);
        String rsp = udp.receiveString();
        return convertToDataBlocks(rsp);
    }

    /**
     * @param rsp a string of data block list, the format is [block1]:[block2]...
     * @return a list of data block
     */
    @NotNull
    private static List<DataBlock> convertToDataBlocks(@NotNull String rsp) {
        if (rsp.equals("")) {
            return new ArrayList<>();
        }
        String[] split = rsp.split(":");
        List<DataBlock> dataBlocks = new ArrayList<>();
        for (String blockStr : split) {
            byte[] bytes = Util.stringToByteArray(blockStr);
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
        List<DataBlock> dataBlocks = DataBlock.convertToBlockList(dataBytesWithCheck, 6);

        // remove check data blocks
        dataBlocks.remove(dataBlocks.size() - 1);
        dataBlocks.remove(dataBlocks.size() - 1);
        return parse(dataBlocks);
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
