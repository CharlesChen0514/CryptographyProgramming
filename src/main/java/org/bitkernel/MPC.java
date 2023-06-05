package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.user.CmdType;

import java.math.BigInteger;

@Slf4j
public class MPC implements Runnable {
    private final Udp udp;
    private final BigInteger rPlusD1;
    private final BigInteger rPlusD2;
    private final String sysName = "mpc";

    public MPC(int port, @NotNull BigInteger rPlusD1, @NotNull BigInteger rPlusD2) {
        udp = new Udp(port);
        this.rPlusD1 = rPlusD1;
        this.rPlusD2 = rPlusD2;
        logger.debug("rPlusD1: {}, rPlusD2: {}", rPlusD1, rPlusD2);
    }

    public void run() {
        while (true) {
            String fFullCmdLine = udp.receiveString();
            response(fFullCmdLine);
        }
    }

    private void response(@NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String name = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            case SMPC_1:
                smpc(name, msg, 1);
                break;
            case SMPC_2:
                smpc(name, msg, 2);
                break;
            default:
        }
    }

    private void smpc(@NotNull String groupName, @NotNull String msg,
                      int type) {
        String[] split = msg.split(":");
        int curId = Integer.parseInt(split[0]);
        String pathStr = split[1];
        BigInteger x = new BigInteger(split[2]);

        String[] path = pathStr.split("-");
        String curUser = path[curId].split(",")[0];
        BigInteger rPlusD = type == 1 ? rPlusD1 : rPlusD2;
        BigInteger add = x.add(rPlusD);
        logger.debug(String.format("%s accept X[%s], return X[%s]", curUser, x, add));

        int nextId = curId + 1;
        if (nextId == path.length) {
            String rsp;
            if (type == 1) {
                rsp = String.format("%s@%s@%s", groupName, CmdType.BASE_D1.cmd, add);
            } else {
                rsp = String.format("%s@%s@%s", groupName, CmdType.BASE_D2.cmd, add);
            }
            udp.send(Config.getMpcMainIp(), Config.getMpcMainPort(), rsp);
        } else {
            String next = path[nextId];
            String[] address = next.split(",");
            String ip = address[1];
            int mpcPort = Integer.parseInt(address[2]);

            String rsp;
            if (type == 1) {
                rsp = String.format("%s@%s@%d:%s:%s", groupName, CmdType.SMPC_1.cmd, nextId, pathStr, add);
            } else {
                rsp = String.format("%s@%s@%d:%s:%s", groupName, CmdType.SMPC_2.cmd, nextId, pathStr, add);
            }
            udp.send(ip, mpcPort, rsp);
        }
    }
}
