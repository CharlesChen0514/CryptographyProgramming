package org.bitkernel.mpc;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.common.CmdType;
import org.bitkernel.storage.StorageGateway;

import java.math.BigInteger;
import java.net.DatagramPacket;
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
    private final StorageGateway storageGateway;

    public MPCMain() {
        udp = new Udp(Config.getMpcMainPort());
        storageGateway = new StorageGateway();
    }

    public static void main(String[] args) {
        MPCMain mpcMain = new MPCMain();
        mpcMain.run();
    }

    public void run() {
        logger.debug("MPC Main start success");
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
            case REGISTER:
                registerUser(pkt, name, msg);
                break;
            case CREATE_GROUP:
                createGroup(name, msg);
                break;
            case JOIN_GROUP:
                joinGroup(name, msg);
                break;
            case GROUP_List:
                getGroupNameList(name);
                break;
            case GENERATE_RSA_KEY_PAIR:
                generateRsaKeyPair(name, msg);
                break;
            case GROUP_NUMBER:
                getGroupNumber(pkt, msg);
                break;
            case SCENARIO3_TEST:
                rsaKeyPariRecover(name, msg);
                break;
            default:
        }
    }

    private void rsaKeyPariRecover(@NotNull String userName, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupName = split[0];
        BigInteger r = new BigInteger(split[1]);
        userInfoMap.get(userName).setR(r);
        Group g = groupMap.get(groupName);

        String rsp;
        if (!already(g)) {
            rsp = "Waiting for authorization from others";
            logger.debug(rsp);
            sendToUser(userName, rsp);
        } else {
            Pair<String, String> path = generateTransferPath(groupName);
            g.setSumD1(getSumD1(groupName, path));
            logger.debug("{}'s sum of d1: {}", groupName, g.getSumD1());
            g.setSumD2(getSumD2(groupName, path));
            logger.debug("{}'s sum of d1: {}", groupName, g.getSumD2());
            g.getMember().forEach(m -> userInfoMap.get(m).setR(null));

            RSAKeyPair rsaKeyPair = generateRSAKeyPair(g.getSumD1(), g.getSumD2());
            boolean flag = storageGateway.checkRecover(g.getMember(), g.getUuid(), rsaKeyPair);
            if (flag) {
                storageGateway.remove(g.getUuid());
                storageGateway.store(g.getMember(), g.getUuid(), rsaKeyPair);
                rsp = String.format("[%s]'s rsa key recover success", g.getName());
                logger.debug(rsp);
                g.getMember().forEach(m -> sendToUser(m, rsp));
            } else {
                rsp = String.format("[%s]'s rsa key recover failed", g.getName());
                logger.error(rsp);
                g.getMember().forEach(m -> sendToUser(m, rsp));
            }
        }
    }

    private void getGroupNumber(@NotNull DatagramPacket pkt, @NotNull String groupUuid) {
        Group group = groupMap.values().stream().
                filter(g -> g.getUuid().equals(groupUuid)).findFirst().get();
        udp.send(pkt, String.valueOf(group.getMember().size()));
    }

    @NotNull
    private BigInteger computeSumD(@NotNull String groupName, @NotNull String msg) {
        BigInteger x = new BigInteger(msg);
        Group group = groupMap.get(groupName);
        for (String name : group.getMember()) {
            UserInfo userInfo = userInfoMap.get(name);
            x = x.subtract(userInfo.getR());
        }
        return x;
    }

    @NotNull
    private Pair<String,String> generateTransferPath(@NotNull String groupName) {
        Group g = groupMap.get(groupName);
        List<Integer> path = new ArrayList<>();
        for (int i = 0; i < g.getMember().size(); i++) {
            path.add(i);
        }
        Collections.shuffle(path);
        printPath(path, g.getMember());

        List<String> namePath = path.stream().map(idx -> g.getMember().get(idx))
                .collect(Collectors.toList());
        StringBuilder sb = new StringBuilder();
        for(String name: namePath) {
            UserInfo userInfo = userInfoMap.get(name);
            sb.append(name).append(",").append(userInfo.getIp()).append(",").append(userInfo.getMpcPort());
            sb.append("-");
        }
        sb.deleteCharAt(sb.length() - 1);
        return new Pair<>(namePath.get(0), sb.toString());
    }

    @NotNull
    private BigInteger getSumD1(@NotNull String groupName, @NotNull Pair<String, String> path) {
        String msg1 = String.format("%s@%s@%d:%s:%s", sysName, CmdType.SMPC_1.cmd, 0, path.getValue(), 0);
        UserInfo userInfo = userInfoMap.get(path.getKey());
        udp.send(userInfo.getIp(), userInfo.getMpcPort(), msg1);
        return computeSumD(groupName, udp.receiveString());
    }

    @NotNull
    private BigInteger getSumD2(@NotNull String groupName, @NotNull Pair<String, String> path) {
        String msg1 = String.format("%s@%s@%d:%s:%s", sysName, CmdType.SMPC_2.cmd, 0, path.getValue(), 0);
        UserInfo userInfo = userInfoMap.get(path.getKey());
        udp.send(userInfo.getIp(), userInfo.getMpcPort(), msg1);
        return computeSumD(groupName, udp.receiveString());
    }

    private boolean already(@NotNull Group g) {
        return g.getMember().stream().allMatch(m -> userInfoMap.get(m).getR() != null);
    }

    private void generateRsaKeyPair(@NotNull String userName, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupName = split[0];
        BigInteger r = new BigInteger(split[1]);
        userInfoMap.get(userName).setR(r);
        Group g = groupMap.get(groupName);

        String rsp;
        if (!already(g)) {
            rsp = "Waiting for authorization from others";
            sendToUser(userName, rsp);
        } else {
            Pair<String, String> path = generateTransferPath(groupName);
            g.setSumD1(getSumD1(groupName, path));
            logger.debug("{}'s sum of d1: {}", groupName, g.getSumD1());
            g.setSumD2(getSumD2(groupName, path));
            logger.debug("{}'s sum of d1: {}", groupName, g.getSumD2());
            g.getMember().forEach(m -> userInfoMap.get(m).setR(null));

            RSAKeyPair rsaKeyPair = generateRSAKeyPair(g.getSumD1(), g.getSumD2());
            storageGateway.store(g.getMember(), g.getUuid(), rsaKeyPair);
            logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPublicKey()));
            logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPrivateKey()));
            rsp = String.format("[%s]'s rsa key generation success", g.getName());
            g.getMember().forEach(m -> sendToUser(m, rsp));
        }
        logger.debug(rsp);
    }

    private void getGroupNameList(@NotNull String userName) {
        List<Group> groupList = groupMap.values().stream().filter(g -> g.contains(userName))
                .collect(Collectors.toList());
        StringBuilder sb = new StringBuilder("The group you are in has:\n");
        for (int i = 0; i < groupList.size(); i++) {
            Group g = groupList.get(i);
            sb.append("\t").append(i).append(") ").append(g.getName())
                    .append(", ").append(g.getUuid()).append(System.lineSeparator());
        }
        sb.deleteCharAt(sb.length() - 1);
        sendToUser(userName, sb.toString());
    }

    private void joinGroup(@NotNull String user, @NotNull String groupUuid) {
        Optional<Group> first = groupMap.values().stream()
                .filter(g -> g.getUuid().equals(groupUuid)).findFirst();
        String msg;
        if (!first.isPresent()) {
            msg = groupUuid;
        } else {
            Group group = first.get();
            group.join(user);
            msg = String.format("%s:%s", group.getName(), group.getUuid());
        }
        String cmd = String.format("%s@%s@%s", sysName, CmdType.GROUP_ID.cmd, msg);
        UserInfo userInfo = userInfoMap.get(user);
        udp.send(userInfo.getIp(), userInfo.getUserPort(), cmd);
    }

    private void createGroup(@NotNull String user, @NotNull String groupName) {
        String msg;
        if (groupMap.containsKey(groupName)) {
            msg = groupName;
        } else {
            Group g = new Group(user, groupName);
            groupMap.put(groupName, g);
            msg = String.format("%s:%s", groupName, g.getUuid());
        }
        String cmd = String.format("%s@%s@%s", sysName, CmdType.GROUP_ID.cmd, msg);
        UserInfo userInfo = userInfoMap.get(user);
        udp.send(userInfo.getIp(), userInfo.getUserPort(), cmd);
    }

    private void sendToUser(@NotNull String user, @NotNull String msg) {
        String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, msg);
        UserInfo userInfo = userInfoMap.get(user);
        udp.send(userInfo.getIp(), userInfo.getUserPort(), cmd);
    }

    private void registerUser(@NotNull DatagramPacket pkt,
                              @NotNull String user, @NotNull String addr) {
        if (userInfoMap.containsKey(user)) {
            logger.debug("{} online", user);
            return;
        }
        String[] split = addr.split(":");
        String clientIp = split[0].trim();
        int clientPort = Integer.parseInt(split[1]);
        int mpcPort = Integer.parseInt(split[2]);
        UserInfo info = new UserInfo(clientIp, clientPort, mpcPort);
        userInfoMap.put(user, info);
        logger.info(String.format("%s register successfully, its socket address: %s:%s, mpc port: %s",
                user, clientIp, clientPort, mpcPort));
        udp.send(pkt, "OK");
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

class Group {
    @Getter
    private final List<String> member = new ArrayList<>();
    private final String master;
    @Getter
    private final String name;
    @Getter
    private final String uuid;
    @Getter
    @Setter
    private BigInteger sumD1;
    @Getter
    @Setter
    private BigInteger sumD2;

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
