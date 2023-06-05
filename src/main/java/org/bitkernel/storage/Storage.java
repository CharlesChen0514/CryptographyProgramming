package org.bitkernel.storage;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.storage.DataBlock;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class Storage {
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