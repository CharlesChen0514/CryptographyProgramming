package org.bitkernel;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.user.CmdType;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

@Slf4j
public class MPC implements Runnable {
    private final Udp udp;
    private final BigInteger rPlusD1;
    private final BigInteger rPlusD2;

    public MPC(int port, @NotNull BigInteger rPlusD1, @NotNull BigInteger rPlusD2) {
        udp = new Udp(port);
        this.rPlusD1 = rPlusD1;
        this.rPlusD2 = rPlusD2;
        logger.debug("rPlusD1: {}, rPlusD2: {}", rPlusD1, rPlusD2);
    }

    public void run() {
//        logger.debug("MPC start success");
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
            case SMPC:
                break;
            default:
        }
    }

    public Pair<String, Integer> getAddr() {
        try {
            String hostAddress = InetAddress.getLocalHost().getHostAddress();
            return new Pair<>(hostAddress, udp.getPort());
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }
}
