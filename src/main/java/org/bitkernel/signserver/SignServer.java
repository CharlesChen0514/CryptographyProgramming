package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.blockchainsystem.Letter;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.storage.StorageGateway;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class SignServer {
    private final RSAKeyPair rsaKeyPair = new RSAKeyPair();
    /** group uuid -> sign request object */
    private final Map<String, SignRequest> signRequestMap = new LinkedHashMap<>();
    /** user name -> symmetric key */
    private final Map<String, SecretKey> secretKeyMap = new LinkedHashMap<>();
    private final Udp udp;
    private final StorageGateway storageGateway = new StorageGateway();
    private final String sysName = "sign server";

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

    private void response(@NotNull DatagramPacket pkt, @NotNull String fullCmdLine) {
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
            case SIGN_REQUEST:
                signRequest(pkt, name, msg);
            default:
        }
    }

    private void getPubKey(@NotNull DatagramPacket pkt) {
        String keyEncodedBase64 = RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPublicKey());
        udp.send(pkt, keyEncodedBase64);
    }

    private void register(@NotNull DatagramPacket pkt, @NotNull String userName,
                          @NotNull String msg) {
        byte[] encrypted = stringToByteArray(msg);
        byte[] decrypt = RSAUtil.decrypt(encrypted, rsaKeyPair.getPrivateKey());
        SecretKey secretKey = new SecretKeySpec(decrypt, "AES");
        secretKeyMap.put(userName, secretKey);
        logger.debug("[{}] register secret key: {}", userName, secretKey.getEncoded());
        udp.send(pkt, "OK");
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

    /**
     * 1. check whether the sign request exists or not <br>
     * 2. if not exist, initiate a new sign request,
     * otherwise authorize the sign request <br>
     * 3. if the sign request is fully authorized,
     * generate the letter and transfer it to the blockchain system
     */
    private void signRequest(@NotNull DatagramPacket pkt, @NotNull String userName,
                             @NotNull String msg) {
        byte[] encrypted = stringToByteArray(msg);
        logger.debug("Sign server accept a cipher text: {}", encrypted);
        if (!secretKeyMap.containsKey(userName)) {
            logger.error("Secret key not found, please register first");
            return;
        }

        SecretKey secretKey = secretKeyMap.get(userName);
        String plainText = new String(AESUtil.decrypt(encrypted, secretKey));
        String[] split = plainText.split(":");
        String groupUuid = split[0].trim();
        String content = split[1].trim();

        String rsp;
        if (!storageGateway.contains(groupUuid)) {
            rsp = "Please generate rsa key pair first";
            String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, rsp);
            udp.send(pkt, cmd);
            return;
        }

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(groupUuid, userName);
        SignRequest signRequest;
        if (signRequestMap.containsKey(groupUuid)) {
            signRequest = signRequestMap.get(groupUuid);
            signRequest.addSubPriKey(userName, subPriKey);
            rsp = "you authorized a signature request";
            logger.debug("[{}] authorized a signature request with message [{}]", userName, content);
        } else {
            PublicKey pubKey = storageGateway.getPubKey(groupUuid);
            udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(),
                    String.format("%s@%s@%s", sysName, CmdType.GROUP_NUMBER.cmd, groupUuid));
            int groupMemberNum = Integer.parseInt(udp.receiveString());
            signRequest = new SignRequest(userName, groupUuid, content,
                    groupMemberNum, subPriKey, pubKey);
            signRequestMap.put(groupUuid, signRequest);
            logger.debug("[{}] initiates a signature request with message [{}]", userName, content);
            rsp = "you initiates a signature request, waiting for authorization from others";
        }
        String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, rsp);
        udp.send(pkt, cmd);

        if (signRequest.isFullyAuthorized()) {
            logger.debug("All users has authorized the sign request");
            Letter letter = signRequest.getLetter();
            udp.send(Config.getBlockChainSysIp(), Config.getBlockChainSysPort(), letter.toString());
            signRequestMap.remove(groupUuid);
        }
    }
}
