package org.bitkernel.user;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Config;
import org.bitkernel.Udp;
import org.bitkernel.enigma.Enigma;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
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
    public Client(@NotNull String username,
                  @NotNull String key) {
        this.username = username;
        this.rootKey = key;

        enigma = new Enigma(Config.getAlphabets(), Config.getPositions());
        udp = new Udp(Config.getClientPort());

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer is [{}]", r);

        d1Str = enigma.encode(key);
        d2Str = enigma.encode(key);
        logger.debug(String.format("[%s's] key is [%s], d1 string is [%s], d2 string is [%s]",
                username, key, d1Str, d2Str));
    }

    public static void main(String[] args) {
        Config.init();

        System.out.print("Please input username: ");
        String userName = in.next();
        System.out.print("Please input key of length 8: ");
        String key = in.next();

        Client client = new Client(userName, key);
        client.register();
        client.guide();
    }

    private void register() {
        try {
            String cmd = String.format("%s@%s@%s:%d", username, CmdType.REGISTER.cmd,
                    InetAddress.getLocalHost().getHostAddress(), Config.getClientPort());
            udp.send(Config.getMpcIp(), Config.getMpcPort(), cmd);
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
            process(fullCmdLine);
        }
    }

    private boolean check(@NotNull String fullCmdLine) {
        // lele@-c@group
        String[] split = fullCmdLine.split("@");
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        if (type == CmdType.EXIT) {
            return split.length == 2;
        } else {
            return split.length == 3;
        }
    }

    private void process(@NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case CREATE_GROUP:
            case JOIN_GROUP:
            case SCENARIO1_TEST:
            case SCENARIO2_TEST:
            case SCENARIO3_TEST:
            case EXIT:
                isRunning = false;
            default:
        }
    }
}
