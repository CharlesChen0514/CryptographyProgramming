package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Util;
import org.bitkernel.blockchainsystem.Letter;
import org.bitkernel.cryptography.RSAUtil;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

@Slf4j
public class SignRequest {
    private final String initiator;
    private final String groupUuid;
    @Getter
    private final Map<String, String> messageMap = new LinkedHashMap<>();
    private final int groupMemberNum;
    private final List<Pair<Integer, byte[]>> subPriKeyList = new ArrayList<>();
    private final PublicKey publicKey;

    public SignRequest(@NotNull String userName, @NotNull String groupUuid,
                       @NotNull String msg, int groupMemberNum,
                       @NotNull Pair<Integer, byte[]> subPriKey,
                       @NotNull PublicKey publicKey) {
        this.initiator = userName;
        this.groupUuid = groupUuid;
        messageMap.put(userName, msg);
        this.groupMemberNum = groupMemberNum;
        subPriKeyList.add(subPriKey);
        this.publicKey = publicKey;
    }

    public boolean isFullyAuthorized() {
        return subPriKeyList.size() == groupMemberNum;
    }

    public void authorized(@NotNull String userName, @NotNull String content,
                           @NotNull Pair<Integer, byte[]> subPriKey) {
        if (messageMap.containsKey(userName)) {
            logger.error("User {} has authorized", userName);
            return;
        }
        messageMap.put(userName, content);
        subPriKeyList.add(subPriKey);
    }

    @NotNull
    public Letter getLetter() {
        MessageDigest md = Util.getMessageDigestInstance();
        byte[] hash = md.digest(messageMap.toString().getBytes());

        PrivateKey privateKey = constructPriKey();
        byte[] signature = RSAUtil.encrypt(hash, privateKey);

        return new Letter(messageMap, signature, publicKey);
    }

    @NotNull
    private PrivateKey constructPriKey() {
        subPriKeyList.sort(Comparator.comparing(Pair::getKey));
        int len = subPriKeyList.stream().map(p -> p.getValue().length)
                .reduce(0, Integer::sum);
        byte[] priKey = new byte[len];
        int pos = 0;
        for (Pair<Integer, byte[]> subPriKey : subPriKeyList) {
            System.arraycopy(subPriKey.getValue(), 0, priKey,
                    pos, subPriKey.getValue().length);
            pos += subPriKey.getValue().length;
        }
        String priKeyString = new String(priKey);
        return RSAUtil.getPrivateKey(priKeyString);
    }
}
