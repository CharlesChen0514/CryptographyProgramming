package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.StorageGateway;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class SignServer {
    private final RSAKeyPair rsaKeyPair = new RSAKeyPair();
    private final Map<String, SignRequest> signRequestMap = new LinkedHashMap<>();
    /** user name -> symmetric key */
    private final Map<String, SecretKey> secretKeyMap = new LinkedHashMap<>();

    @NotNull
    public PublicKey getRSAPubKey() {
        return rsaKeyPair.getPublicKey();
    }

    /**
     * Exchange of symmetric key via asymmetric encryption
     * @param source user name
     * @param encryptedSecretKey encrypted symmetric key via RSA public key
     */
    public void register(@NotNull String source,
                         @NotNull byte[] encryptedSecretKey) {
        byte[] decrypt = RSAUtil.decrypt(encryptedSecretKey, rsaKeyPair.getPrivateKey());
        SecretKey secretKey = new SecretKeySpec(decrypt, "AES");
        secretKeyMap.put(source, secretKey);
        logger.debug("[{}] register secret key: {}", source, secretKey.getEncoded());
    }

    /**
     * Initiates a signature request
     * @param source user name
     * @param encryptReq encrypted signature request message via ASE key
     */
    public void newSignRequest(@NotNull String source, @NotNull byte[] encryptReq,
                               @NotNull StorageGateway storageGateway) {
        logger.debug("Sign server accept a cipher text: {}", encryptReq);
        if (!secretKeyMap.containsKey(source)) {
            logger.error("Secret key not found, please register first");
            return;
        }
        SecretKey secretKey = secretKeyMap.get(source);
        byte[] decrypt = AESUtil.decrypt(encryptReq, secretKey);
        String signReqString = new String(decrypt);
        String[] split = signReqString.split("-");

        String groupTag = split[0].trim();
        String msg = split[1].trim();
        logger.debug("[{}] initiates a signature request with message [{}]", source, msg);

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(source, groupTag);
        PublicKey pubKey = storageGateway.getPubKey(groupTag);
        int groupMemberNum = Integer.parseInt(groupTag.substring(0, 1));
        SignRequest signRequest = new SignRequest(source, groupTag, msg,
                groupMemberNum, subPriKey, pubKey);
        signRequestMap.put(groupTag, signRequest);
    }

    /**
     * Authorized a signature request
     * @param source user name
     * @param encryptReq encrypted authorized request message via ASE key
     * @return If the authorized user meet the requirement, return the
     * SignRequest Object, otherwise return null
     */
    public SignRequest authorized(@NotNull String source, @NotNull byte[] encryptReq,
                                  @NotNull StorageGateway storageGateway) {
        logger.debug("Sign server accept a cipher text: {}", encryptReq);
        if (!secretKeyMap.containsKey(source)) {
            logger.error("Secret key not found, please register first");
            return null;
        }
        SecretKey secretKey = secretKeyMap.get(source);
        byte[] decrypt = AESUtil.decrypt(encryptReq, secretKey);
        String groupTag = new String(decrypt);

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(source, groupTag);
        SignRequest signRequest = signRequestMap.get(groupTag);
        signRequest.addSubPriKey(source, subPriKey);
        logger.debug("[{}] authorized the signature request", source);

        if (signRequest.isFullyAuthorized()) {
            logger.debug("All users has authorized the sign request");
            return signRequest;
        }
        return null;
    }
}
