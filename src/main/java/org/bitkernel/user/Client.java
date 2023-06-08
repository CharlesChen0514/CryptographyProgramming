package org.bitkernel.user;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bitkernel.Util;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.mpc.MPC;
import org.bitkernel.common.Udp;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

@Slf4j
public class Client {
    private static final Scanner in = new Scanner(System.in);
    private final String username;
    private final Udp udp;
    /** Symmetric Key */
    private final SecretKey secretKey;
    private final MPC mpc;
    /** group name -> group uuid */
    private final Map<String, String> groupUuidMap = new LinkedHashMap<>();

    public Client(@NotNull String username) {
        this.username = username;
        this.udp = new Udp();
        this.secretKey = AESUtil.generateKey();
        this.mpc = new MPC();
    }

    public static void main(String[] args) {
        System.out.print("Please input username: ");
        String userName = in.next();

        Client client = new Client(userName);
        client.register();
        client.startLocalService();
        client.guide();
    }

    /**
     * Register to MPC Main and Sign Server
     */
    private void register() {
        try {
            // register to MPC Main
            String cmd = String.format("%s@%s@%s:%d:%d", username, CmdType.REGISTER.cmd,
                    InetAddress.getLocalHost().getHostAddress(), udp.getPort(),
                    mpc.getUdp().getPort());
            udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), cmd);
            if (udp.receiveString().equals("OK")) {
                logger.debug("Register to MPC Main success");
            } else {
                logger.error("Register to MPC Main failed");
            }

            // register to sign server
            cmd = String.format("%s@%s@ ", username, CmdType.GET_PUB_KEY.cmd);
            udp.send(Config.getSignServerIp(), Config.getSignServerPort(), cmd);
            String pubkeyString = udp.receiveString();
            PublicKey publicKey = RSAUtil.getPublicKey(pubkeyString);
            String msg = String.format("%s:%d:%d:%s", InetAddress.getLocalHost().getHostAddress(),
                    udp.getPort(), mpc.getUdp().getPort(), RSAUtil.getKeyEncodedBase64(secretKey));
            byte[] encrypt = RSAUtil.encrypt(msg.getBytes(), publicKey);
            cmd = String.format("%s@%s@%s", username, CmdType.REGISTER.cmd, Arrays.toString(encrypt));
            udp.send(Config.getSignServerIp(), Config.getSignServerPort(), cmd);
            if (udp.receiveString().equals("OK")) {
                logger.debug("Register to sign server success");
            } else {
                logger.error("Register to sign server failed");
            }
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Start local service, including receiver and mpc instance.
     */
    private void startLocalService() {
        Thread t1 = new Thread(() -> {
            while (true) {
                DatagramPacket pkt = udp.receivePkt();
                String fullCmdLine = udp.pktToString(pkt);
                String[] split = fullCmdLine.split("@");
                CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
                switch (type) {
                    case RESPONSE:
                        display(split[0], split[2]);
                        break;
                    case GROUP_ID:
                    case JOIN_GROUP:
                        addGroupMsg(split[2]);
                        break;
                }
            }
        });
        t1.start();
        logger.debug("start udp receiver successfully");

        Thread t2 = new Thread(mpc);
        t2.start();
        logger.info("start mpc instance successfully, its socket port is: {}", mpc.getUdp().getPort());
    }

    private void display(@NotNull String source, @NotNull String msg) {
        if (source.equals("sign server")) {
            byte[] bytes = Util.stringToByteArray(msg);
            byte[] decrypt = AESUtil.decrypt(bytes, secretKey);
            System.out.println(new String(decrypt));
        } else {
            System.out.println(msg);
        }
    }

    /**
     * Add group information to local
     * @param msg the format is groupName:groupUuid
     */
    private void addGroupMsg(@NotNull String msg) {
        String[] msgArr = msg.split(":");
        if (msgArr.length == 1) {
            System.out.printf("Add group [%s] failed%n", msg);
        } else {
            groupUuidMap.put(msgArr[0], msgArr[1]);
            System.out.printf("Add group [%s] success, uuid: %s%n", msgArr[0], msgArr[1]);
        }
    }

    /**
     * User command navigation
     */
    private void guide() {
        System.out.println("Command guide:");
        CmdType.menu.forEach(System.out::println);
        in.nextLine();
        while (true) {
            String inCmdLine = in.nextLine();
            String fullCmdLine = username + "@" + inCmdLine;
            if (!check(fullCmdLine)) {
                System.out.println("Command error, please re-entered");
                continue;
            }
            // Command standardization
            String fFullCmdLine = fullCmdLine.split("@").length == 2 ?
                    fullCmdLine + "@" + " " : fullCmdLine;
            process(fFullCmdLine);
        }
    }

    /**
     * Check the command whether is correctly formatted
     */
    private boolean check(@NotNull String fullCmdLine) {
        // lele@-c@group
        String[] split = fullCmdLine.split("@");
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        if (type == CmdType.EXIT || type == CmdType.GROUP_List ||
                type == CmdType.HELP) {
            return split.length == 2;
        } else {
            return split.length == 3;
        }
    }

    private void process(@NotNull String fFullCmdLine) {
        String[] split = fFullCmdLine.split("@");
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        if (type == null) {
            System.out.println("Command error, please re-entered");
            return;
        }

        switch (type) {
            case CREATE_GROUP:
            case JOIN_GROUP:
            case GROUP_List:
                udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), fFullCmdLine);
                break;
            case GENERATE_RSA_KEY_PAIR:
            case RSA_KER_PAIR_RECOVER:
                generateRsaKeyPair(fFullCmdLine);
                break;
            case SIGN_REQUEST:
                signRequest(fFullCmdLine);
                break;
            case HELP:
                CmdType.menu.forEach(System.out::println);
                break;
            case EXIT:
                System.exit(-1);
                break;
            default:
        }
    }

    @NotNull
    private String replaceGroupNameToUuid(@NotNull String fFullCmdLine) {
        String[] split = fFullCmdLine.split("@");
        String[] msgArr = split[2].split(":");
        msgArr[0] = groupUuidMap.get(msgArr[0]);
        split[2] = StringUtils.join(msgArr, ":");
        return StringUtils.join(split, "@");
    }

    /**
     * 1. user input a key of length 8 <br>
     * 2. generate 128-bit random number r <br>
     * 3. generate d1 and d2 via enigma machine <br>
     * 4. set the value of (r + d) to mpc instance <br>
     * 5. send request to MPC-Main <br>
     */
    private void generateRsaKeyPair(@NotNull String fFullCmdLine) {
        System.out.print("Please input key of length 8: ");
        String key = in.next();
        in.nextLine();

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        BigInteger r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer is [{}]", r);

        Enigma enigma = new Enigma(Config.getAlphabets(), Config.getPositions());
        String d1Str = enigma.encode(key);
        String d2Str = enigma.encode(key);
        logger.debug(String.format("[%s's] key is [%s], d1 string is [%s], d2 string is [%s]",
                username, key, d1Str, d2Str));
        mpc.setRPlusD1(r.add(new BigInteger(d1Str.getBytes())));
        mpc.setRPlusD2(r.add(new BigInteger(d2Str.getBytes())));
        logger.debug("rPlusD1: {}, rPlusD2: {}", mpc.getRPlusD1(), mpc.getRPlusD2());

        String sysCmd = replaceGroupNameToUuid(fFullCmdLine) + ":" + r;
        udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), sysCmd);
    }

    /**
     * Initiating or authorizing signature requests. change the group name to
     * group uuid and then send to the Sign server.
     * @param fFullCmdLine e.g. chen@-s2t@groupName:hello
     */
    private void signRequest(@NotNull String fFullCmdLine) {
        String sysCmd = replaceGroupNameToUuid(fFullCmdLine);
        String[] split = sysCmd.split("@");
        // symmetric encrypted transmission
        split[2] = Arrays.toString(AESUtil.encrypt(split[2].getBytes(), secretKey));
        udp.send(Config.getSignServerIp(), Config.getSignServerPort(), StringUtils.join(split, "@"));
    }
}
