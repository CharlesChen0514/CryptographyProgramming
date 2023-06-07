package org.bitkernel.common;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@AllArgsConstructor
public enum CmdType {
    REGISTER("-r", "register", "-r@clientIp:clientPort:mpcPort:R"),
    CREATE_GROUP("-c", "create a group", "-c@groupName"),
    JOIN_GROUP("-j", "join a group", "-j@groupUuid"),
    GROUP_List("-gl", "query the groups you are in", "-gl"),
    GENERATE_RSA_KEY_PAIR("-s1t", "generate group rsa key pair", "-s1t@groupName"),
    SIGN_REQUEST("-s2t", "sign request", "-s2t@groupName:msg"),
    RSA_KER_PAIR_RECOVER("-s3t", "group rsa key pair recover", "-s3t@groupName"),
    RESPONSE("-rsp", "response message", "-rsp@msg"),
    EXIT("-q", "exit", "-q"),
    HELP("-h", "help", "-h"),
    GROUP_ID("-gi", "", "-gi@groupName:uuid"),

    SMPC_1("-smpc_1", "SMPC", "-smpc_1@idx:path:X"),
    SMPC_2("-smpc_2", "SMPC", "-smpc_2@idx:path:X"),

    HEART_BEAT("-hb", "", "-hb@ "),
    PUT_PUB_KEY_BLOCK("-ppkb1", "", "-ppkb1@groupUuid:block"),
    PUT_PRI_KEY_BLOCK("-ppkb2", "", "-ppkb2@groupUuid:userName:block"),
    GET_PUB_KEY_BLOCKS("-gpkb1", "", "-gpkb1@groupUuid"),
    GET_PRI_KEY_BLOCKS("-gpkb2", "", "-gpkb2@groupUuid:userName"),
    REMOVE("-remove", "", "-remove@groupUuid"),

    GET_PUB_KEY("-gpk", "", "-gpk@ "),
    GROUP_NUMBER("-gn", "", "-gn@ ");

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
        menu.add(GROUP_List);
        menu.add(GENERATE_RSA_KEY_PAIR);
        menu.add(SIGN_REQUEST);
        menu.add(RSA_KER_PAIR_RECOVER);
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