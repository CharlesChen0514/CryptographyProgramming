package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.enigma.Enigma;
import org.bitkernel.enigma.EnigmaMessage;
import org.bitkernel.cryptography.RSAUtil;

import javax.crypto.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;

@Slf4j
public class User {
    @Getter
    private final String name;
    private final Enigma encryptMachine;
    private String rootKey;
    @Getter
    private EnigmaMessage d1;
    @Getter
    private EnigmaMessage d2;
    /** 128-bit random bit integer "R" */
    @Getter
    private final BigInteger r;
    /** Symmetric Key */
    private final SecretKey secretKey;

    public User(@NotNull String name) {
        this.name = name;
        this.encryptMachine = new Enigma();
        this.secretKey = AESUtil.generateKey();
        // According to the name to set the enigma initial position
        BigInteger num = new BigInteger(name.getBytes());
        int pos = num.mod(BigInteger.valueOf(26)).intValue();
        encryptMachine.setPos(pos, (pos * 2 + 1) % 26, (pos * 3 + 2) % 26);

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer [{}]", r);
    }

    /**
     * @param publicKey RSA public key
     * @return encrypted symmetric key
     */
    public byte[] getSecretKey(@NotNull PublicKey publicKey) {
        return RSAUtil.encrypt(secretKey.getEncoded(), publicKey);
    }

    /**
     * Encrypted messages via symmetric encryption
     * @return encrypted sign request
     */
    @NotNull
    public byte[] generateSignReq(@NotNull String groupTag, @NotNull String msg) {
        String signReqString = String.format("%s-%s", groupTag, msg);
        return AESUtil.encrypt(signReqString.getBytes(), secretKey);
    }

    /**
     * Encrypted messages via symmetric encryption
     * @return encrypted authorized request
     */
    @NotNull
    public byte[] generateAuthorizedReq(@NotNull String groupTag) {
        return AESUtil.encrypt(groupTag.getBytes(), secretKey);
    }

    /**
     * According to the key to generate the d1 and d2 number
     * @param key the root key input by the user
     */
    public void generateEncryptedNumber(@NotNull String key) {
        this.rootKey = key;
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
