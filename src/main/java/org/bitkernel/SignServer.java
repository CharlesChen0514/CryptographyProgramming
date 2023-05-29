package org.bitkernel;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

@Slf4j
public class SignServer {
    private final RSAKeyPair rsaKeyPair = new RSAKeyPair();
    private final Map<String, SignRequest> signRequestMap = new LinkedHashMap<>();

    @NotNull
    public PublicKey getRSAPubKey() {
        return rsaKeyPair.getPublicKey();
    }

    public void newSignRequest(@NotNull byte[] encryptReq,
                               @NotNull StorageGateway storageGateway) {
        logger.debug("Sign server accept a cipher text: {}", encryptReq);
        byte[] decrypt = RSAUtil.decrypt(encryptReq, rsaKeyPair.getPrivateKey());
        String signReqString = new String(decrypt);
        String[] split = signReqString.split("-");

        String userName = split[0].trim();
        String groupTag = split[1].trim();
        String msg = split[2].trim();
        logger.debug("[{}] initiates a signature request with message [{}]", userName, msg);

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(userName, groupTag);
        PublicKey pubKey = storageGateway.getPubKey(groupTag);
        int groupMemberNum = Integer.parseInt(groupTag.substring(0, 1));
        SignRequest signRequest = new SignRequest(userName, groupTag, msg,
                groupMemberNum, subPriKey, pubKey);
        signRequestMap.put(groupTag, signRequest);
    }

    public void authorized(@NotNull byte[] encryptReq,
                           @NotNull StorageGateway storageGateway,
                           @NotNull BlockChainSystem blockChainSystem) {
        logger.debug("Sign server accept a cipher text: {}", encryptReq);
        byte[] decrypt = RSAUtil.decrypt(encryptReq, rsaKeyPair.getPrivateKey());
        String authorizedString = new String(decrypt);
        String[] split = authorizedString.split("-");

        String userName = split[0].trim();
        String groupTag = split[1].trim();

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(userName, groupTag);
        SignRequest signRequest = signRequestMap.get(groupTag);
        signRequest.addSubPriKey(userName, subPriKey);
        logger.debug("[{}] authorized the signature request", userName);

        if (signRequest.isFullyAuthorized()) {
            logger.debug("All users has authorized the sign request, send letter to blockchain");
            signRequest.sendLetter(blockChainSystem);
        }
    }
}

@Slf4j
class SignRequest {
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

    public void sendLetter(@NotNull BlockChainSystem blockChainSystem) {
        MessageDigest md = getMessageDigestInstance();
        byte[] hash = md.digest(msg.getBytes());

        PrivateKey privateKey = constructPriKey();
        byte[] signature = RSAUtil.encrypt(hash, privateKey);

        Letter letter = new Letter(msg, signature, publicKey);
        blockChainSystem.acceptLetter(letter);
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
