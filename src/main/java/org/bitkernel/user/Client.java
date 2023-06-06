package org.bitkernel.user;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
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
import java.util.Scanner;

@Slf4j
public class Client {
    private static final Scanner in = new Scanner(System.in);
    private final String username;
    private final Enigma enigma;
    private boolean isRunning = true;
    private final Udp udp;
    private final String rootKey;
    @Getter
    private final String d1Str;
    @Getter
    private final String d2Str;
    /** 128-bit random bit integer "R" */
    @Getter
    private final BigInteger r;
    /** Symmetric Key */
    private final SecretKey secretKey;
    private MPC mpc;

    public Client(@NotNull String username,
                  @NotNull String key) {
        this.username = username;
        this.rootKey = key;

        enigma = new Enigma(Config.getAlphabets(), Config.getPositions());
        udp = new Udp();

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer is [{}]", r);

        d1Str = enigma.encode(key);
        d2Str = enigma.encode(key);
        logger.debug(String.format("[%s's] key is [%s], d1 string is [%s], d2 string is [%s]",
                username, key, d1Str, d2Str));
        this.secretKey = AESUtil.generateKey();
        mpc = new MPC(getDWithR(d1Str), getDWithR(d2Str));
    }

    public static void main(String[] args) {
        System.out.print("Please input username: ");
        String userName = in.next();
        System.out.print("Please input key of length 8: ");
        String key = in.next();

        Client client = new Client(userName, key);
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
                }
            }
        });
        t1.start();
        logger.debug("start udp receiver successfully");

        Thread t2 = new Thread(mpc);
        t2.start();
        logger.info("start mpc instance successfully, its socket port is: {}", mpc.getUdp().getPort());
    }

    @NotNull
    public BigInteger getDWithR(@NotNull String dString) {
        BigInteger d = new BigInteger(dString.getBytes());
        return r.add(d);
    }

    private void register() {
        try {
            // register to MPC Main
            String cmd = String.format("%s@%s@%s:%d:%d:%s", username, CmdType.REGISTER.cmd,
                    InetAddress.getLocalHost().getHostAddress(), udp.getPort(),
                    mpc.getUdp().getPort(), r);
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
        if (type == CmdType.EXIT || type == CmdType.GROUP_List) {
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
            case SCENARIO1_TEST:
                udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), fFullCmdLine);
                break;
            case SCENARIO2_TEST:
            case SCENARIO3_TEST:
            case EXIT:
                isRunning = false;
            default:
        }
    }
}
