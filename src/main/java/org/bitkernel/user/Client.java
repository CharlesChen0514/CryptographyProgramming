package org.bitkernel.user;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Config;
import org.bitkernel.enigma.Enigma;

import java.util.Scanner;

@Slf4j
public class Client {
    private static final Scanner in = new Scanner(System.in);
    private final String username;
    private Enigma enigma;
    private boolean isRunning = true;
    public Client(@NotNull String username) {
        this.username = username;
        enigma = new Enigma(Config.getAlphabets(), Config.getPositions());
    }

    public static void main(String[] args) {
        Config.init();
        System.out.print("Please input your username: ");
        String userName = in.next();
        Client client = new Client(userName);
        client.guide();
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
