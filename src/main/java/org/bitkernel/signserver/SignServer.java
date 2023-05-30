package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.StorageGateway;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

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

    public SignRequest authorized(@NotNull byte[] encryptReq,
                                  @NotNull StorageGateway storageGateway) {
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
            logger.debug("All users has authorized the sign request");
            return signRequest;
        }
        return null;
    }
}
