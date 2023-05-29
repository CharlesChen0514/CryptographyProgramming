package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.enigma.Enigma;
import org.bitkernel.enigma.Message;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

@Slf4j
public class User {
    @Getter
    private final String name;
    private final Enigma enigma;
    private String key;
    @Getter
    private Message d1Message;
    @Getter
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

    public void generateEncryptedNumber(@NotNull String key) {
        this.key = key;
        d1Message = enigma.encode(key);
        d2Message = enigma.encode(key);
        logger.info(String.format("%s's key is [%s], d1 string is [%s], d2 string is [%s]",
                name, key, d1Message.getStr(), d2Message.getStr()));
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
