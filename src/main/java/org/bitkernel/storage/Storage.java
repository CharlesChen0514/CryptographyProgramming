package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;

import java.net.DatagramPacket;
import java.util.*;

@Slf4j
@NoArgsConstructor
public class Storage {
    /** Group tag -> user name -> data block */
    private final Map<String, Map<String, List<DataBlock>>> priKeyDataBlockMap = new LinkedHashMap<>();
    /** Group tag -> data block */
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
            case REMOVE:
                remove(pkt, msg);
                break;
            default:
        }
    }

    private void remove(@NotNull DatagramPacket pkt, @NotNull String groupUuid) {
        priKeyDataBlockMap.remove(groupUuid);
        pubKeyDataBlockMap.remove(groupUuid);
    }

    public void putPriKeyBlock(@NotNull DatagramPacket pkt, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupUuid = split[0];
        String username = split[1];
        byte[] bytes = stringToByteArray(split[2]);
        DataBlock block = new DataBlock(bytes);
        putPriKeyBlock(groupUuid, username, block);
        logger.debug("Store the {}th pri key block, length: {}",
                block.getBlockId(), block.getBytes().length);
        udp.send(pkt, "TRUE");
    }

    @NotNull
    private byte[] stringToByteArray(@NotNull String str) {
        String[] strArray = str.replaceAll("[\\[\\]\\s]", "").split(",");
        byte[] byteArray = new byte[strArray.length];
        for (int i = 0; i < strArray.length; i++) {
            byteArray[i] = Byte.parseByte(strArray[i]);
        }
        return byteArray;
    }

    public void putPriKeyBlock(@NotNull String groupUuid,
                               @NotNull String userName,
                               @NotNull DataBlock dataBlock) {
        priKeyDataBlockMap.putIfAbsent(groupUuid, new LinkedHashMap<>());
        priKeyDataBlockMap.get(groupUuid).putIfAbsent(userName, new ArrayList<>());
        priKeyDataBlockMap.get(groupUuid).get(userName).add(dataBlock);
    }

    public void getPriKeyDataBlocks(@NotNull DatagramPacket pkt, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupUuid = split[0];
        String userName = split[1];

        List<DataBlock> priKeyDataBlocks = getPriKeyDataBlocks(groupUuid, userName);
        udp.send(pkt, serialize(priKeyDataBlocks));
    }

    @NotNull
    public List<DataBlock> getPriKeyDataBlocks(@NotNull String groupUuid,
                                               @NotNull String userName) {
        if (!priKeyDataBlockMap.containsKey(groupUuid)) {
            logger.error("Group uuid {} not found", groupUuid);
            return new ArrayList<>();
        }
        if (!priKeyDataBlockMap.get(groupUuid).containsKey(userName)) {
            logger.error("User name {} not found", userName);
            return new ArrayList<>();
        }
        return priKeyDataBlockMap.get(groupUuid).get(userName);
    }

    public void putPubKeyBlock(@NotNull DatagramPacket pkt, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupUuid = split[0];
        byte[] bytes = stringToByteArray(split[1]);
        DataBlock block = new DataBlock(bytes);
        putPubKeyBlock(groupUuid, block);
        logger.debug("Store the {}th pub key block, length: {}",
                block.getBlockId(), block.getBytes().length);
        udp.send(pkt, "TRUE");
    }

    public void putPubKeyBlock(@NotNull String groupUuid,
                               @NotNull DataBlock dataBlock) {
        pubKeyDataBlockMap.putIfAbsent(groupUuid, new ArrayList<>());
        pubKeyDataBlockMap.get(groupUuid).add(dataBlock);
    }

    public void getPubKeyBlocks(@NotNull DatagramPacket pkt, @NotNull String msg) {
        List<DataBlock> pubKeyBlocks = getPubKeyBlocks(msg);
        udp.send(pkt, serialize(pubKeyBlocks));
    }

    @NotNull
    private static String serialize(@NotNull List<DataBlock> pubKeyBlocks) {
        StringBuilder sb = new StringBuilder();
        for (DataBlock data: pubKeyBlocks) {
            sb.append(Arrays.toString(data.getBytes())).append(":");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    @NotNull
    public List<DataBlock> getPubKeyBlocks(@NotNull String groupUuid) {
        if (!pubKeyDataBlockMap.containsKey(groupUuid)) {
            logger.error("Group tag {} not found", groupUuid);
            return new ArrayList<>();
        }
        return pubKeyDataBlockMap.get(groupUuid);
    }
}