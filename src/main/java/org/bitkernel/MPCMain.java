package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.user.CmdType;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class MPCMain {
    public static final int R_BYTE_NUM = 16;
    public static final int RSA_BYTE_NUM = 128;
    private final Udp udp;
    /** group name -> group object */
    private final Map<String, Group> groupMap = new LinkedHashMap<>();
    private final Map<String, UserInfo> userInfoMap = new LinkedHashMap<>();
    private final String sysName = "mpc main";

    public MPCMain() {
        udp = new Udp(Config.getMpcMainPort());
    }

    public static void main(String[] args) {
        MPCMain mpcMain = new MPCMain();
        mpcMain.run();
    }

    public void run() {
        logger.debug("MPC Main start success");
        while (true) {
            String fullCmdLine = udp.receiveString();
            response(fullCmdLine);
        }
    }

    private void response(@NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String userName = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case REGISTER:
                registerUser(userName, msg);
                break;
            case CREATE_GROUP:
                createGroup(userName, msg);
                break;
            case JOIN_GROUP:
                joinGroup(userName, msg);
                break;
            case GROUP_List:
                getGroupNameList(userName);
                break;
            case SCENARIO1_TEST:
                generateTransferPath(msg);
                break;
            default:
        }
    }

    private void generateTransferPath(@NotNull String groupName) {
        Group group = groupMap.get(groupName);
        List<Integer> path = new ArrayList<>();
        for (int i = 0; i < group.getMember().size(); i++) {
            path.add(i);
        }
        Collections.shuffle(path);
        printPath(path, group.getMember());

        List<String> namePath = path.stream().map(idx -> group.getMember().get(idx))
                .collect(Collectors.toList());
        String msg = String.format("%s@%s@%d:%s:%s", sysName, CmdType.SMPC.cmd, 0, namePath, 0);
//        Pair<String, Integer> addr = mpcMap.get(namePath.get(0)).getAddr();
//        udp.send(addr.getKey(), addr.getValue(), msg);
    }

    private void getGroupNameList(@NotNull String userName) {
        List<String> names = groupMap.values().stream().filter(g -> g.contains(userName))
                .map(Group::getName).collect(Collectors.toList());
        String msg = String.format("The group you are in has: %s", names);
        sendToUser(userName, msg);
    }

    private void joinGroup(@NotNull String user, @NotNull String groupUuid) {
        Optional<Group> first = groupMap.values().stream()
                .filter(g -> g.getUuid().equals(groupUuid)).findFirst();
        String msg;
        if (!first.isPresent()) {
            msg = String.format("Non-existent group of uuid [%s]", groupUuid);
        } else {
            Group group = first.get();
            group.join(user);
            msg = String.format("join group [%s] success", group.getName());
        }
        sendToUser(user, msg);
    }

    private void createGroup(@NotNull String user, @NotNull String groupName) {
        String msg;
        if (groupMap.containsKey(groupName)) {
            msg = String.format("create group [%s] failed", groupName);
        } else {
            Group g = new Group(user, groupName);
            groupMap.put(groupName, g);
            msg = String.format("create group [%s] success, uuid: %s", groupName, g.getUuid());
        }
        sendToUser(user, msg);
    }

    private void sendToUser(@NotNull String user, @NotNull String msg) {
        String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, msg);
        UserInfo userInfo = userInfoMap.get(user);
        udp.send(userInfo.getIp(), userInfo.getUserPort(), cmd);
    }

    private void registerUser(@NotNull String user, @NotNull String addr) {
        String[] split = addr.split(":");
        String clientIp = split[0].trim();
        int clientPort = Integer.parseInt(split[1]);
        int mpcPort = Integer.parseInt(split[2]);
        BigInteger r = new BigInteger(split[3]);
        UserInfo info = new UserInfo(clientIp, clientPort, mpcPort, r);
        userInfoMap.put(user, info);
        logger.info(String.format("%s register successfully, its socket address: %s:%s, mpc port: %s, r: %s",
                user, clientIp, clientPort, mpcPort, r));
    }

    /**
     * generate the message transfer path randomly
     *
     * @param users user group
     * @return transfer path, e.g. [2, 1, 3] : 2 -> 1 -> 3
     */
    @NotNull
    public List<Integer> generatePath(@NotNull User[] users) {
        List<Integer> path = new ArrayList<>();
        for (int i = 0; i < users.length; i++) {
            path.add(i);
        }
        Collections.shuffle(path);
        printPath(path, users);
        return path;
    }

    /**
     * Print the transfer path by name
     *
     * @param path the transfer path by index
     */
    @NotNull
    public static void printPath(@NotNull List<Integer> path,
                                 @NotNull User[] group) {
        StringBuilder sb = new StringBuilder();
        for (int idx : path) {
            User user = group[idx];
            sb.append(user.getName()).append("->");
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);
        logger.debug("The SMPC transfer path is: {}", sb);
    }

    @NotNull
    public static void printPath(@NotNull List<Integer> path,
                                 @NotNull List<String> group) {
        StringBuilder sb = new StringBuilder();
        for (int idx : path) {
            sb.append(group.get(idx)).append("->");
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);
        logger.debug("The SMPC transfer path is: {}", sb);
    }

    /**
     * @param x       the aggregate value by D and R
     * @param rValues R value list
     * @return the sum of D
     */
    @NotNull
    public BigInteger getSumD(@NotNull BigInteger x,
                              @NotNull BigInteger... rValues) {
        BigInteger sumD = new BigInteger(x.toByteArray());
        for (BigInteger r : rValues) {
            sumD = sumD.subtract(r);
        }
        return sumD;
    }

    /**
     * Join all username by '@' to generate a group tag
     *
     * @return group tag
     */
    @NotNull
    public String generateGroupTag(@NotNull User[] users) {
        StringBuilder sb = new StringBuilder();
        sb.append(users.length).append("@");
        for (User user : users) {
            sb.append(user.getName()).append("@");
        }
        sb.deleteCharAt(sb.length() - 1);
        logger.debug("Generate a group tag is {}", sb);
        return sb.toString();
    }

    /**
     * Base on the d1 sum and d2 sum to generate the RSA key pair
     */
    @NotNull
    public RSAKeyPair generateRSAKeyPair(@NotNull BigInteger d1Sum,
                                         @NotNull BigInteger d2Sum) {
        BigInteger d1SumPadding = dataPadding(d1Sum);
        BigInteger d2SumPadding = dataPadding(d2Sum);
        logger.debug("D1 sum [{}] expanding to [{}]", d1Sum, d1SumPadding);
        logger.debug("D2 sum [{}] expanding to [{}]", d2Sum, d2SumPadding);
        BigInteger p = findNextPrime(d1SumPadding);
        BigInteger q = findNextPrime(d2SumPadding);
        logger.debug("Find P [{}]", p);
        logger.debug("Find Q [{}]", q);
        return new RSAKeyPair(p, q);
    }

    @NotNull
    private BigInteger findNextPrime(@NotNull BigInteger base) {
        while (!base.isProbablePrime(1024)) {
            base = base.add(BigInteger.ONE);
        }
        return base;
    }

    @NotNull
    public static BigInteger dataPadding(@NotNull BigInteger data) {
        byte[] input = data.toByteArray();
        if (input.length > R_BYTE_NUM) {
            logger.error("Input error, the byte length {} is not as expected {}",
                    input.length, R_BYTE_NUM);
            return BigInteger.ZERO;
        }
        // Standardize the data to 128 bit
        byte[] inputFormatted = new byte[R_BYTE_NUM];
        System.arraycopy(input, 0, inputFormatted, R_BYTE_NUM - input.length, input.length);
        // Expanded to 1024 bits in equal proportion
        byte[] output = new byte[RSA_BYTE_NUM];
        int factor = output.length / inputFormatted.length;
        for (int i = 0; i < inputFormatted.length; i++) {
            output[i * factor] = inputFormatted[i];
        }
        return new BigInteger(output);
    }
}

@AllArgsConstructor
class UserInfo {
    @Getter
    private final String ip;
    @Getter
    private final int userPort;
    @Getter
    private final int mpcPort;
    @Getter
    private final BigInteger r;
}

class Group {
    @Getter
    private final List<String> member = new ArrayList<>();
    private final String master;
    @Getter
    private final String name;
    @Getter
    private final String uuid;
    public Group(@NotNull String user, @NotNull String name) {
        this.master = user;
        this.name = name;
        member.add(user);
        uuid = getUUID32();
    }

    public void join(@NotNull String user) {
        member.add(user);
    }

    public boolean contains(@NotNull String user) {
        return member.contains(user);
    }

    @NotNull
    public static String getUUID32() {
        return UUID.randomUUID().toString().replace("-", "").toLowerCase();
    }
}
