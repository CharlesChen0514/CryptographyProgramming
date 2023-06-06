package org.bitkernel.mpc;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
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

    private void response(DatagramPacket pkt, @NotNull String fullCmdLine) {
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
            case SCENARIO1_TEST:
                generateTransferPath(msg);
                break;
            case BASE_D1:
                setSumD1(name, msg);
                break;
            case BASE_D2:
                setSumD2(name, msg);
                break;
            default:
        }
    }

    private void setSumD2(@NotNull String groupName, @NotNull String msg) {
        BigInteger sumD = computeSumD(groupName, msg);
        Group g = groupMap.get(groupName);
        g.setSumD2(sumD);
        logger.debug("{}'s sum of d2: {}", groupName, sumD);
        if (g.getSumD1() != null && g.getSumD2() != null) {
            RSAKeyPair rsaKeyPair = generateRSAKeyPair(g.getSumD1(), g.getSumD2());
            storageGateway.store(g.getMember(), g.getUuid(), rsaKeyPair);
            logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPublicKey()));
            logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPrivateKey()));
        }
    }

    private void setSumD1(@NotNull String groupName, @NotNull String msg) {
        BigInteger sumD = computeSumD(groupName, msg);
        Group g = groupMap.get(groupName);
        g.setSumD1(sumD);
        logger.debug("{}'s sum of d1: {}", groupName, sumD);
        if (g.getSumD1() != null && g.getSumD2() != null) {
            RSAKeyPair rsaKeyPair = generateRSAKeyPair(g.getSumD1(), g.getSumD2());
            storageGateway.store(g.getMember(), g.getUuid(), rsaKeyPair);
            logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPublicKey()));
            logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPrivateKey()));
        }
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
        StringBuilder sb = new StringBuilder();
        for(String name: namePath) {
            UserInfo userInfo = userInfoMap.get(name);
            sb.append(name).append(",").append(userInfo.getIp()).append(",").append(userInfo.getMpcPort());
            sb.append("-");
        }
        sb.deleteCharAt(sb.length() - 1);

        String msg1 = String.format("%s@%s@%d:%s:%s", groupName, CmdType.SMPC_1.cmd, 0, sb, 0);
        String msg2 = String.format("%s@%s@%d:%s:%s", groupName, CmdType.SMPC_2.cmd, 0, sb, 0);
        UserInfo userInfo = userInfoMap.get(namePath.get(0));
        udp.send(userInfo.getIp(), userInfo.getMpcPort(), msg1);
        udp.send(userInfo.getIp(), userInfo.getMpcPort(), msg2);
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

    private void registerUser(DatagramPacket pkt, @NotNull String user, @NotNull String addr) {
        if (userInfoMap.containsKey(user)) {
            logger.debug("{} online", user);
            return;
        }
        String[] split = addr.split(":");
        String clientIp = split[0].trim();
        int clientPort = Integer.parseInt(split[1]);
        int mpcPort = Integer.parseInt(split[2]);
        BigInteger r = new BigInteger(split[3]);
        UserInfo info = new UserInfo(clientIp, clientPort, mpcPort, r);
        userInfoMap.put(user, info);
        logger.info(String.format("%s register successfully, its socket address: %s:%s, mpc port: %s, r: %s",
                user, clientIp, clientPort, mpcPort, r));
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
