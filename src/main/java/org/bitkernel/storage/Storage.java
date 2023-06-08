package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Util;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;

import java.net.DatagramPacket;
import java.util.*;

@Slf4j
@NoArgsConstructor
public class Storage {
    /** hash key -> data block */
    private final Map<String, List<DataBlock>> priKeyDataBlockMap = new LinkedHashMap<>();
    /** hash key -> data block */
    private final Map<String, List<DataBlock>> pubKeyDataBlockMap = new LinkedHashMap<>();
    private Udp udp;
    private int idx;

    public Storage(int idx) {
        this.idx = idx;
        udp = new Udp(Config.getStoragePort(idx));
    }

    public static void main(String[] args) {
        int idx = Integer.parseInt(args[0]);
        Storage storage = new Storage(idx);
        storage.run();
    }

    public void run() {
        logger.debug("Storage{} instance start success", idx);
        while (true) {
            DatagramPacket pkt = udp.receivePkt();
            String fullCmdLine = udp.pktToString(pkt);
            response(pkt, fullCmdLine);
        }
    }

    private void response(@NotNull DatagramPacket pkt, @NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String name = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case HEART_BEAT:
                udp.send(pkt, "ALIVE");
                break;
            case PUT_PUB_KEY_BLOCK:
                putPubKeyBlock(pkt, msg);
                break;
            case PUT_PRI_KEY_BLOCK:
                putPriKeyBlock(pkt, msg);
                break;
            case GET_PUB_KEY_BLOCKS:
                getPubKeyBlocks(pkt, msg);
                break;
            case GET_PRI_KEY_BLOCKS:
                getPriKeyDataBlocks(pkt, msg);
                break;
            case REMOVE_PUB_KEY:
                removePubKey(pkt, msg);
                break;
            case REMOVE_PRI_KEY:
                removePriKey(pkt, msg);
                break;
            default:
        }
    }
    private void removePriKey(@NotNull DatagramPacket pkt, @NotNull String priHashKey) {
        priKeyDataBlockMap.remove(priHashKey);
    }

    private void removePubKey(@NotNull DatagramPacket pkt, @NotNull String pubHashKey) {
        pubKeyDataBlockMap.remove(pubHashKey);
    }

    public void putPriKeyBlock(@NotNull DatagramPacket pkt, @NotNull String msg) {
        String[] split = msg.split(":");
        String hashKey = split[0];
        byte[] bytes = Util.stringToByteArray(split[1]);
        DataBlock block = new DataBlock(bytes);
        putPriKeyBlock(hashKey, block);
        logger.debug("Store the {}th pri key block, length: {}",
                block.getBlockId(), block.getBytes().length);
        udp.send(pkt, "TRUE");
    }

    public void putPriKeyBlock(@NotNull String hashKey,
                               @NotNull DataBlock dataBlock) {
        priKeyDataBlockMap.putIfAbsent(hashKey, new ArrayList<>());
        priKeyDataBlockMap.get(hashKey).add(dataBlock);
    }

    public void getPriKeyDataBlocks(@NotNull DatagramPacket pkt, @NotNull String msg) {
        List<DataBlock> priKeyDataBlocks = getPriKeyDataBlocks(msg);
        udp.send(pkt, serialize(priKeyDataBlocks));
    }

    @NotNull
    public List<DataBlock> getPriKeyDataBlocks(@NotNull String hashKey) {
        if (!priKeyDataBlockMap.containsKey(hashKey)) {
            logger.error("Data blocks not found with hash {}", hashKey);
            return new ArrayList<>();
        }
        return priKeyDataBlockMap.get(hashKey);
    }

    public void putPubKeyBlock(@NotNull DatagramPacket pkt, @NotNull String msg) {
        String[] split = msg.split(":");
        String hashKey = split[0];
        byte[] bytes = Util.stringToByteArray(split[1]);
        DataBlock block = new DataBlock(bytes);
        putPubKeyBlock(hashKey, block);
        logger.debug("Store the {}th pub key block, length: {}",
                block.getBlockId(), block.getBytes().length);
        udp.send(pkt, "TRUE");
    }

    public void putPubKeyBlock(@NotNull String hashKey,
                               @NotNull DataBlock dataBlock) {
        pubKeyDataBlockMap.putIfAbsent(hashKey, new ArrayList<>());
        pubKeyDataBlockMap.get(hashKey).add(dataBlock);
    }

    public void getPubKeyBlocks(@NotNull DatagramPacket pkt, @NotNull String msg) {
        List<DataBlock> pubKeyBlocks = getPubKeyBlocks(msg);
        udp.send(pkt, serialize(pubKeyBlocks));
    }

    @NotNull
    private static String serialize(@NotNull List<DataBlock> pubKeyBlocks) {
        if (pubKeyBlocks.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (DataBlock data: pubKeyBlocks) {
            sb.append(Arrays.toString(data.getBytes())).append(":");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    @NotNull
    public List<DataBlock> getPubKeyBlocks(@NotNull String hashKey) {
        if (!pubKeyDataBlockMap.containsKey(hashKey)) {
            logger.error("Data block not found with hash {}", hashKey);
            return new ArrayList<>();
        }
        return pubKeyDataBlockMap.get(hashKey);
    }
}