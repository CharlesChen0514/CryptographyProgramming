package org.bitkernel.user;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@AllArgsConstructor
public enum CmdType {
    CREATE_GROUP("-c", "create a group", "-c@groupName"),
    JOIN_GROUP("-j", "join a group", "-j@groupName"),
    SCENARIO1_TEST("-s1t", "scenario 1 test", "-s1t@groupName"),
    SCENARIO2_TEST("-s2t", "scenario 2 test", "-s2t@groupName"),
    SCENARIO3_TEST("-s3t", "scenario 3 test", "-s3t@groupName"),
    EXIT("-q", "exit", "-q");

    public final String cmd;
    public final String description;
    public final String example;
    public static final Map<String, CmdType> cmdToEnumMap;
    /** Stored command type for presentation to users */
    public static final Set<CmdType> menu;

    static {
        cmdToEnumMap = new LinkedHashMap<>();
        for (CmdType cmdType : CmdType.values()) {
            cmdToEnumMap.put(cmdType.cmd, cmdType);
        }

        menu = new LinkedHashSet<>();
        menu.add(CREATE_GROUP);
        menu.add(JOIN_GROUP);
        menu.add(SCENARIO1_TEST);
        menu.add(SCENARIO2_TEST);
        menu.add(SCENARIO3_TEST);
        menu.add(EXIT);
    }

//    @NotNull
//    public static String constructCmdString(@NotNull String... args) {
//        return joinDelimiter(args, sym);
//    }

    @NotNull
    public String toString() {
        return String.format("\t%s, %s, %s", cmd, description, example);
    }
}