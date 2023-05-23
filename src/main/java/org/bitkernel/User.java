package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

@Slf4j
public class User {
    @Getter
    private final String name;
    private final Enigma enigma;
    private String key;
    private Message d1Message;
    private Message d2Message;
    @Getter
    private final BigInteger r;

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
        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
    }

    public void generateEncryption(@NotNull String key) {
        logger.debug("{}'s key is {}", name, key);
        this.key = key;
        d1Message = enigma.encode(key);
        d2Message = enigma.encode(key);
        logger.debug("d1 string is {}", d1Message.getStr());
        logger.debug("d2 string is {}", d2Message.getStr());
    }

    @NotNull
    public BigInteger addD1WithR(@NotNull BigInteger start) {
        BigInteger add = start.add(getDWithR(d1Message));
        logger.debug(String.format("%s accept X(%s), return X(%s)", name, start, add));
        return add;
    }

    @NotNull
    public BigInteger addD2WithR(@NotNull BigInteger start) {
        BigInteger add = start.add(getDWithR(d2Message));
        logger.debug(String.format("%s accept X(%s), return X(%s)", name, start, add));
        return add;
    }

    @NotNull
    public BigInteger getDWithR(@NotNull Message dString) {
        BigInteger d = new BigInteger(dString.getStr().getBytes());
        return r.add(d);
    }
}
