package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.storage.StorageGateway;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class SignServer {
    private final RSAKeyPair rsaKeyPair = new RSAKeyPair();
    private final Map<String, SignRequest> signRequestMap = new LinkedHashMap<>();
    /** user name -> symmetric key */
    private final Map<String, SecretKey> secretKeyMap = new LinkedHashMap<>();
    private final Udp udp;

    public SignServer() {
        udp = new Udp(Config.getSignServerPort());
    }

    public static void main(String[] args) {
        SignServer signServer = new SignServer();
        signServer.run();
    }

    public void run() {
        logger.debug("Sign server start success");
        while (true) {
            DatagramPacket pkt = udp.receivePkt();
            String fullCmdLine = udp.pktToString(pkt);
            response(pkt, fullCmdLine);
        }
    }

    private void response(DatagramPacket pkt, @NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String name = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case GET_PUB_KEY:
                getPubKey(pkt);
                break;
            case REGISTER:
                register(pkt, name, msg);
                break;
            default:
        }
    }

    private void getPubKey(@NotNull DatagramPacket pkt) {
        String keyEncodedBase64 = RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPublicKey());
        udp.send(pkt, keyEncodedBase64);
    }

    private void register(@NotNull DatagramPacket pkt, @NotNull String userName,
                          @NotNull String msg) {
        byte[] encrypted = StringToByteArray(msg);
        byte[] decrypt = RSAUtil.decrypt(encrypted, rsaKeyPair.getPrivateKey());
        SecretKey secretKey = new SecretKeySpec(decrypt, "AES");
        secretKeyMap.put(userName, secretKey);
        logger.debug("[{}] register secret key: {}", userName, secretKey.getEncoded());
        udp.send(pkt, "OK");
    }

    @NotNull
    private byte[] StringToByteArray(@NotNull String str) {
        String[] strArray = str.replaceAll("[\\[\\]\\s]", "").split(",");
        byte[] byteArray = new byte[strArray.length];
        for (int i = 0; i < strArray.length; i++) {
            byteArray[i] = Byte.parseByte(strArray[i]);
        }
        return byteArray;
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

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(groupTag, source);
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

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(groupTag, source);
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
