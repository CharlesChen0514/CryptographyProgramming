package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.enigma.Enigma;
import org.bitkernel.enigma.EnigmaMessage;

import java.math.BigInteger;
import java.security.SecureRandom;

@Slf4j
public class User {
    @Getter
    private final String name;
    private final Enigma encryptMachine;
    private String key;
    @Getter
    private EnigmaMessage d1;
    @Getter
    private EnigmaMessage d2;
    /** 128-bit random bit integer "R" */
    @Getter
    private final BigInteger r;

    public User(@NotNull String name) {
        this.name = name;
        this.encryptMachine = new Enigma();

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer [{}]", r);
    }

    /**
     * According to the key to generate the d1 and d2 number
     * @param key the root key input by the user
     */
    public void generateEncryptedNumber(@NotNull String key) {
        this.key = key;
        d1 = encryptMachine.encode(key);
        d2 = encryptMachine.encode(key);
        logger.debug(String.format("[%s's] key is [%s], d1 string is [%s], d2 string is [%s]",
                name, key, d1.getStr(), d2.getStr()));
    }

    @NotNull
    public BigInteger addD1WithR(@NotNull BigInteger start) {
        BigInteger add = start.add(getDWithR(d1));
        logger.debug(String.format("%s accept X[%s], return X[%s]", name, start, add));
        return add;
    }

    @NotNull
    public BigInteger addD2WithR(@NotNull BigInteger start) {
        BigInteger add = start.add(getDWithR(d2));
        logger.debug(String.format("%s accept X[%s], return X[%s]", name, start, add));
        return add;
    }

    @NotNull
    public BigInteger getDWithR(@NotNull EnigmaMessage dString) {
        BigInteger d = new BigInteger(dString.getStr().getBytes());
        return r.add(d);
    }
}
