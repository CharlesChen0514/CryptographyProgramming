package org.bitkernel.signserver;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Util;
import org.bitkernel.blockchainsystem.Letter;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.storage.StorageGateway;
import sun.misc.BASE64Decoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.security.PublicKey;
import java.util.Arrays;
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
    /** username -> user info */
    private final Map<String, UserInfo> userInfoMap = new LinkedHashMap<>();

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
        byte[] encrypted = Util.stringToByteArray(msg);
        byte[] decrypt = RSAUtil.decrypt(encrypted, rsaKeyPair.getPrivateKey());
        msg = new String(decrypt);
        String[] split = msg.split(":");
        String clientIp = split[0].trim();
        int clientPort = Integer.parseInt(split[1]);
        int mpcPort = Integer.parseInt(split[2]);
        UserInfo info = new UserInfo(clientIp, clientPort, mpcPort);
        userInfoMap.put(userName, info);
        logger.info(String.format("%s register successfully, its socket address: %s:%s, mpc port: %s",
                userName, clientIp, clientPort, mpcPort));

        byte[] key;
        try {
            key = new BASE64Decoder().decodeBuffer(split[3]);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        secretKeyMap.put(userName, secretKey);
        logger.debug("[{}] register secret key: {}", userName, secretKey.getEncoded());
        udp.send(pkt, "OK");
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
        byte[] encrypted = Util.stringToByteArray(msg);
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
            sendToUser(userName, rsp);
            return;
        }

        if (storageGateway.blockNum(groupUuid) < 4) {
            rsp = "Data lost, please recover key";
            sendToUser(userName, rsp);
            return;
        }

        Pair<Integer, byte[]> subPriKey = storageGateway.getSubPriKey(groupUuid, userName);
        SignRequest signRequest;
        if (signRequestMap.containsKey(groupUuid)) {
            signRequest = signRequestMap.get(groupUuid);
            if (signRequest.getMessageMap().containsKey(userName)) {
                rsp = "You have unfinished signature requests";
            } else {
                signRequest.authorized(userName, content, subPriKey);
                rsp = "you authorized a signature request";
                logger.debug("[{}] authorized a signature request with message [{}]", userName, content);
            }
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
        sendToUser(userName, rsp);

        if (signRequest.isFullyAuthorized()) {
            logger.debug("All users has authorized the sign request");
            Letter letter = signRequest.getLetter();
            udp.send(Config.getBlockChainSysIp(), Config.getBlockChainSysPort(), letter.toString());
            signRequestMap.remove(groupUuid);
            for (Map.Entry<String, String> entry : signRequest.getMessageMap().entrySet()) {
                rsp = String.format("Your signature request in [%s] with [%s] sent to the blockchain system", groupUuid, entry.getValue());
                sendToUser(entry.getKey(), rsp);
            }
        }
    }

    private void sendToUser(@NotNull String user, @NotNull String msg) {
        SecretKey secretKey = secretKeyMap.get(user);
        byte[] encrypt = AESUtil.encrypt(msg.getBytes(), secretKey);
        String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, Arrays.toString(encrypt));
        UserInfo userInfo = userInfoMap.get(user);
        udp.send(userInfo.getIp(), userInfo.getUserPort(), cmd);
    }
}

class UserInfo {
    @Getter
    private final String ip;
    @Getter
    private final int userPort;
    @Getter
    private final int mpcPort;
    @Getter
    @Setter
    private BigInteger r;

    public UserInfo(String ip, int userPort, int mpcPort) {
        this.ip = ip;
        this.userPort = userPort;
        this.mpcPort = mpcPort;
    }
}
