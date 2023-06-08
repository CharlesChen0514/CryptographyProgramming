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
    /** group uuid -> group object */
    private final Map<String, Group> groupMap = new LinkedHashMap<>();
    /** username -> user info */
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

    private void response(@NotNull DatagramPacket pkt,
                          @NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String name = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case REGISTER:
                registerUser(pkt, name, msg);
                break;
            case CREATE_GROUP:
                createGroup(pkt, name, msg);
                break;
            case JOIN_GROUP:
                joinGroup(pkt, name, msg);
                break;
            case GROUP_List:
                getGroupNameList(pkt, name);
                break;
            case GENERATE_RSA_KEY_PAIR:
                generateRsaKeyPair(name, msg);
                break;
            case GROUP_NUMBER:
                getGroupNumber(pkt, msg);
                break;
            case RSA_KER_PAIR_RECOVER:
                rsaKeyPariRecover(name, msg);
                break;
            default:
        }
    }

    /**
     * @param addr format is clientIp:clientPort:mpcPort
     */
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

    /**
     * 1. get the list of groups the user belongs to <br>
     * 2. check whether there has a group with the same name <br>
     * 3. If so, group creation failed, otherwise create a new group
     */
    private void createGroup(@NotNull DatagramPacket pkt,
                             @NotNull String user, @NotNull String groupName) {
        List<Group> groupList = groupMap.values().stream().filter(g -> g.contains(user))
                .collect(Collectors.toList());
        String msg;
        if (groupList.stream().anyMatch(g -> g.getGroupName().equals(groupName))) {
            msg = groupName;
            logger.debug("Group with the same name cannot be created");
        } else {
            Group g = new Group(user, groupName);
            groupMap.put(g.getUuid(), g);
            msg = String.format("%s:%s", groupName, g.getUuid());
            logger.debug("[{}] create a group [{}]", user, groupName);
        }
        String cmd = String.format("%s@%s@%s", sysName, CmdType.GROUP_ID.cmd, msg);
        udp.send(pkt, cmd);
    }

    /**
     * join a group via UUID
     */
    private void joinGroup(@NotNull DatagramPacket pkt,
                           @NotNull String user, @NotNull String groupUuid) {
        String msg;
        if (!groupMap.containsKey(groupUuid)) {
            msg = groupUuid;
            logger.debug("Group {} is not exist", groupUuid);
        } else {
            Group g = groupMap.get(groupUuid);
            g.join(user);
            msg = String.format("%s:%s", g.getGroupName(), g.getUuid());
            logger.debug("{} join the {}", user, g.getGroupName());
        }
        String cmd = String.format("%s@%s@%s", sysName, CmdType.GROUP_ID.cmd, msg);
        udp.send(pkt, cmd);
    }

    /**
     * get the list of groups the user belongs to
     */
    private void getGroupNameList(@NotNull DatagramPacket pkt,
                                  @NotNull String userName) {
        List<Group> groupList = groupMap.values().stream().filter(g -> g.contains(userName))
                .collect(Collectors.toList());
        StringBuilder sb = new StringBuilder("The group you are in has:\n");
        for (int i = 0; i < groupList.size(); i++) {
            Group g = groupList.get(i);
            sb.append("\t").append(i).append(") ").append(g.getGroupName())
                    .append(", ").append(g.getUuid()).append(System.lineSeparator());
        }
        sb.deleteCharAt(sb.length() - 1);
        String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, sb);
        udp.send(pkt, cmd);
    }

    private boolean alreadyToGenerateRsaKeyPair(@NotNull Group g) {
        return g.getMember().stream().allMatch(m -> userInfoMap.get(m).getR() != null);
    }

    private void generateRsaKeyPair(@NotNull String userName, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupUuid = split[0];
        BigInteger r = new BigInteger(split[1]);
        userInfoMap.get(userName).setR(r);
        Group g = groupMap.get(groupUuid);

        String rsp;
        if (storageGateway.contains(groupUuid)) {
            rsp = "The rsa key already exists and does not need to be regenerated";
            sendToUser(userName, rsp);
        } else if (!alreadyToGenerateRsaKeyPair(g)) {
            rsp = "Waiting for authorization from others";
            sendToUser(userName, rsp);
        } else {
            RSAKeyPair rsaKeyPair = generateRsaKeyPair(g);
            storageGateway.store(g.getMember(), g.getUuid(), rsaKeyPair);
            logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPublicKey()));
            logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(rsaKeyPair.getPrivateKey()));
            sendToUser(userName, "you authorized the key generation");
            rsp = String.format("[%s]'s rsa key generation success", g.getGroupName());
            g.getMember().forEach(m -> sendToUser(m, rsp));
        }
        logger.debug(rsp);
    }

    /**
     * 1. get sum of d1 via SMPC <br>
     * 2. get sum of d2 via SMPC <br>
     * 3. expanding d1 and d2 to 1024 bit <br>
     * 4. find large prime number P and Q based on sumD1 and sumD2 <br>
     * 5. based on P and Q generate RSA key pair <br>
     */
    @NotNull
    private RSAKeyPair generateRsaKeyPair(@NotNull Group g) {
        Pair<String, String> path = generateTransferPath(g.getUuid());
        g.setSumD1(getSumD1(g.getUuid(), path));
        logger.debug("{}'s sum of d1: {}", g.getGroupName(), g.getSumD1());
        g.setSumD2(getSumD2(g.getUuid(), path));
        logger.debug("{}'s sum of d1: {}", g.getGroupName(), g.getSumD2());
        g.getMember().forEach(m -> userInfoMap.get(m).setR(null));

        BigInteger d1SumPadding = dataExpanding(g.getSumD1());
        BigInteger d2SumPadding = dataExpanding(g.getSumD2());
        logger.debug("D1 sum [{}] expanding to [{}]", g.getSumD1(), d1SumPadding);
        logger.debug("D2 sum [{}] expanding to [{}]", g.getSumD2(), d2SumPadding);
        BigInteger p = findNextPrime(d1SumPadding);
        BigInteger q = findNextPrime(d2SumPadding);
        logger.debug("Find P [{}]", p);
        logger.debug("Find Q [{}]", q);
        return new RSAKeyPair(p, q);
    }

    /**
     * 1. generate rsa key pair when all user is fully authorized <br>
     * 2. check the new key pair whether recover correctly <br>
     * 3. if so, recover success, otherwise failed.
     */
    private void rsaKeyPariRecover(@NotNull String userName, @NotNull String msg) {
        String[] split = msg.split(":");
        String groupUuid = split[0];
        BigInteger r = new BigInteger(split[1]);
        userInfoMap.get(userName).setR(r);
        Group g = groupMap.get(groupUuid);

        String rsp;
        if (!storageGateway.contains(groupUuid)) {
            rsp = "Please generate rsa key pair first";
            sendToUser(userName, rsp);
            return;
        }

        if (!alreadyToGenerateRsaKeyPair(g)) {
            rsp = "Waiting for authorization from others";
            logger.debug(rsp);
            sendToUser(userName, rsp);
        } else {
            RSAKeyPair rsaKeyPair = generateRsaKeyPair(g);
            boolean flag = storageGateway.checkRecover(g.getMember(), g.getUuid(), rsaKeyPair);
            if (flag) {
                storageGateway.remove(g.getUuid());
                storageGateway.store(g.getMember(), g.getUuid(), rsaKeyPair);
                rsp = String.format("[%s]'s rsa key recover success", g.getGroupName());
                logger.debug(rsp);
                g.getMember().forEach(m -> sendToUser(m, rsp));
            } else {
                rsp = String.format("[%s]'s rsa key recover failed", g.getGroupName());
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
    private BigInteger computeSumD(@NotNull String groupUuid, @NotNull String msg) {
        BigInteger x = new BigInteger(msg);
        Group group = groupMap.get(groupUuid);
        for (String name : group.getMember()) {
            UserInfo userInfo = userInfoMap.get(name);
            x = x.subtract(userInfo.getR());
        }
        return x;
    }

    /**
     * Generate the messaging path for SMPC
     */
    @NotNull
    private Pair<String,String> generateTransferPath(@NotNull String groupUuid) {
        Group g = groupMap.get(groupUuid);
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

    @NotNull
    private BigInteger getSumD1(@NotNull String groupUuid, @NotNull Pair<String, String> path) {
        String msg1 = String.format("%s@%s@%d:%s:%s", sysName, CmdType.SMPC_1.cmd, 0, path.getValue(), 0);
        UserInfo userInfo = userInfoMap.get(path.getKey());
        udp.send(userInfo.getIp(), userInfo.getMpcPort(), msg1);
        return computeSumD(groupUuid, udp.receiveString());
    }

    @NotNull
    private BigInteger getSumD2(@NotNull String groupUuid, @NotNull Pair<String, String> path) {
        String msg1 = String.format("%s@%s@%d:%s:%s", sysName, CmdType.SMPC_2.cmd, 0, path.getValue(), 0);
        UserInfo userInfo = userInfoMap.get(path.getKey());
        udp.send(userInfo.getIp(), userInfo.getMpcPort(), msg1);
        return computeSumD(groupUuid, udp.receiveString());
    }

    private void sendToUser(@NotNull String user, @NotNull String msg) {
        String cmd = String.format("%s@%s@%s", sysName, CmdType.RESPONSE.cmd, msg);
        UserInfo userInfo = userInfoMap.get(user);
        udp.send(userInfo.getIp(), userInfo.getUserPort(), cmd);
    }

    @NotNull
    private BigInteger findNextPrime(@NotNull BigInteger base) {
        while (!base.isProbablePrime(1024)) {
            base = base.add(BigInteger.ONE);
        }
        return base;
    }

    /**
     * Expanding data to {@link #RSA_BYTE_NUM} bytes
     */
    @NotNull
    public static BigInteger dataExpanding(@NotNull BigInteger d) {
        byte[] input = d.toByteArray();
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
    private final String creator;
    @Getter
    private final String groupName;
    @Getter
    private final String uuid;
    @Getter
    @Setter
    private BigInteger sumD1;
    @Getter
    @Setter
    private BigInteger sumD2;

    public Group(@NotNull String user, @NotNull String groupName) {
        this.creator = user;
        this.groupName = groupName;
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
