package org.bitkernel.user;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bitkernel.common.CmdType;
import org.bitkernel.common.Config;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.mpc.MPC;
import org.bitkernel.common.Udp;
import org.bitkernel.enigma.Enigma;

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
    private final Enigma enigma;
    private boolean isRunning = true;
    private final Udp udp;
    /** Symmetric Key */
    private final SecretKey secretKey;
    private final MPC mpc;
    private final Map<String, String> groupUuidMap = new LinkedHashMap<>();

    public Client(@NotNull String username) {
        this.username = username;
        enigma = new Enigma(Config.getAlphabets(), Config.getPositions());
        udp = new Udp();
        this.secretKey = AESUtil.generateKey();
        mpc = new MPC();
    }

    public static void main(String[] args) {
        System.out.print("Please input username: ");
        String userName = in.next();

        Client client = new Client(userName);
        client.register();
        client.startLocalService();
        client.guide();
    }

    private void startLocalService() {
        Thread t1 = new Thread(() -> {
            while (isRunning) {
                DatagramPacket pkt = udp.receivePkt();
                String fullCmdLine = udp.pktToString(pkt);
                String[] split = fullCmdLine.split("@");
                CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
                switch (type) {
                    case RESPONSE:
                        System.out.println(split[2]);
                        break;
                    case GROUP_ID:
                    case JOIN_GROUP:
                        addGroup(split[2]);
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

    private boolean addGroup(@NotNull String msg) {
        String[] msgArr = msg.split(":");
        if (msgArr.length == 1) {
            System.out.printf("Add group [%s] failed%n", msg);
            return false;
        } else {
            groupUuidMap.put(msgArr[0], msgArr[1]);
            System.out.printf("Add group [%s] success, uuid: %s%n", msgArr[0], msgArr[1]);
            return true;
        }
    }

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
            byte[] encrypt = RSAUtil.encrypt(secretKey.getEncoded(), publicKey);
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

    private void guide() {
        System.out.println("Command guide:");
        CmdType.menu.forEach(System.out::println);
        in.nextLine();
        while (isRunning) {
            String inCmdLine = in.nextLine();
            String fullCmdLine = username + "@" + inCmdLine;
            if (!check(fullCmdLine)) {
                Printer.displayLn("Command error, please re-entered");
                continue;
            }
            String fFullCmdLine = fullCmdLine.split("@").length == 2 ?
                    fullCmdLine + "@" + " " : fullCmdLine;
            process(fFullCmdLine);
        }
    }

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
        switch (type) {
            case CREATE_GROUP:
            case JOIN_GROUP:
            case GROUP_List:
                udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), fFullCmdLine);
                break;
            case GENERATE_RSA_KEY_PAIR:
                scenario1Test(fFullCmdLine);
                break;
            case SCENARIO2_TEST:
                scenario2Test(fFullCmdLine);
                break;
            case SCENARIO3_TEST:
                scenario3Test(fFullCmdLine);
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

    private void scenario1Test(@NotNull String fFullCmdLine) {
        System.out.print("Please input key of length 8: ");
        String key = in.next();
        in.nextLine();

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        BigInteger r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer is [{}]", r);

        String d1Str = enigma.encode(key);
        String d2Str = enigma.encode(key);
        logger.debug(String.format("[%s's] key is [%s], d1 string is [%s], d2 string is [%s]",
                username, key, d1Str, d2Str));
        mpc.setRPlusD1(r.add(new BigInteger(d1Str.getBytes())));
        mpc.setRPlusD2(r.add(new BigInteger(d2Str.getBytes())));
        logger.debug("rPlusD1: {}, rPlusD2: {}", mpc.getRPlusD1(), mpc.getRPlusD2());

        udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), fFullCmdLine + ":" + r);
    }

    private void scenario3Test(@NotNull String fFullCmdLine) {
        String[] split = fFullCmdLine.split("@");
        if (split.length != 3 || !groupUuidMap.containsKey(split[2])) {
            System.out.println("Command error, please re-entered");
            return;
        }
        split[2] = groupUuidMap.get(split[2]);
        String join = StringUtils.join(split, "@");
        udp.send(Config.getSignServerIp(), Config.getSignServerPort(), join);
    }

    private void scenario2Test(@NotNull String fFullCmdLine) {
        String[] split = fFullCmdLine.split("@");
        String[] msgArr = split[2].split(":");
        if (msgArr.length != 2 || !groupUuidMap.containsKey(msgArr[0])) {
            System.out.println("Command error, please re-entered");
            return;
        }
        msgArr[0] = groupUuidMap.get(msgArr[0]);
        String msg = StringUtils.join(msgArr, ":");
        split[2] = Arrays.toString(AESUtil.encrypt(msg.getBytes(), secretKey));
        String join = StringUtils.join(split, "@");
        udp.send(Config.getSignServerIp(), Config.getSignServerPort(), join);
    }
}
