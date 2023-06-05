package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.user.CmdType;

@Slf4j
public class MPC {
    private final Udp udp;

    public MPC(int port) {
        udp = new Udp(port);
    }

    public void run() {
        logger.debug("MPC start success");
        while (true) {
            String fFullCmdLine = udp.receiveString();
            response(fFullCmdLine);
        }
    }

    private void response(@NotNull String fullCmdLine) {
        String[] split = fullCmdLine.split("@");
        String userName = split[0];
        String msg = split[2];
        CmdType type = CmdType.cmdToEnumMap.get(split[1].trim());
        switch (type) {
            default:
        }
    }
}
