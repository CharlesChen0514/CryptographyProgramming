package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Random;

@Slf4j
public class User {
    private final String name;
    private final Enigma enigma;
    private String key;
    private Message d1Message;
    private Message d2Message;

    public User(@NotNull String name) {
        logger.debug("{} online", name);
        this.name = name;
        enigma = new Enigma();
        Random random = new Random();
        int idx1 = random.nextInt(26);
        int idx2 = random.nextInt(26);
        int idx3 = random.nextInt(26);
        enigma.setPos(idx1, idx2, idx3);
        logger.debug(String.format("The initial position of user %s's enigma is set to [%d, %d, %d]",
                name, idx1, idx2, idx3));
    }

    public void generateEncryption(@NotNull String key) {
        logger.debug("{}'s key is {}", name, key);
        this.key = key;
        d1Message = enigma.encode(key);
        d2Message = enigma.encode(key);
        logger.debug("d1 string is {}", d1Message.getStr());
        logger.debug("d2 string is {}", d2Message.getStr());
    }

    public byte[] getD1Bytes() {
        return d1Message.getStr().getBytes();
    }

    public byte[] getD2Bytes() {
        return d2Message.getStr().getBytes();
    }
}
