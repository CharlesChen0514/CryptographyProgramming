package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Letter;
import org.bitkernel.cryptography.RSAUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

@Slf4j
public class SignRequest {
    private final String initiator;
    private final String groupTag;
    private final String msg;
    private final int groupMemberNum;
    private final List<Pair<Integer, byte[]>> subPriKeyList = new ArrayList<>();
    private final Set<String> authorizedUserList = new HashSet<>();
    private final PublicKey publicKey;

    public SignRequest(@NotNull String userName, @NotNull String groupTag,
                       @NotNull String msg, int groupMemberNum,
                       @NotNull Pair<Integer, byte[]> subPriKey,
                       @NotNull PublicKey publicKey) {
        this.initiator = userName;
        this.groupTag = groupTag;
        this.msg = msg;
        this.groupMemberNum = groupMemberNum;
        subPriKeyList.add(subPriKey);
        authorizedUserList.add(userName);
        this.publicKey = publicKey;
    }

    public boolean isFullyAuthorized() {
        return subPriKeyList.size() == groupMemberNum;
    }

    public void addSubPriKey(@NotNull String userName,
                             @NotNull Pair<Integer, byte[]> subPriKey) {
        if (authorizedUserList.contains(userName)) {
            logger.error("User {} has authorized", userName);
            return;
        }
        authorizedUserList.add(userName);
        subPriKeyList.add(subPriKey);
    }

    @NotNull
    public Letter getLetter() {
        MessageDigest md = getMessageDigestInstance();
        byte[] hash = md.digest(msg.getBytes());

        PrivateKey privateKey = constructPriKey();
        byte[] signature = RSAUtil.encrypt(hash, privateKey);

        return new Letter(msg, signature, publicKey);
    }

    public static MessageDigest getMessageDigestInstance() {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage());
        }
        return md;
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
