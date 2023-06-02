package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.cryptography.AESUtil;
import org.bitkernel.enigma.Enigma;
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
    private String d1Str;
    @Getter
    private String d2Str;
    /** 128-bit random bit integer "R" */
    @Getter
    private final BigInteger r;
    /** Symmetric Key */
    private final SecretKey secretKey;

    public User(@NotNull String name) {
        this.name = name;
        int[] ps = {0, 1, 2};
        this.encryptMachine = new Enigma("abcdefghijklmnopqrstuvwxyz", ps);
        this.secretKey = AESUtil.generateKey();
//        logger.debug(String.format("The initial position of user [%s's] enigma is set to [%d, %d, %d]",
//                name, idx1, idx2, idx3));

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer [{}]", r);
    }

    public User(@NotNull String name, @NotNull String alphabets,
                @NotNull int[] ps) {
        this.name = name;
        this.encryptMachine = new Enigma(alphabets, ps);
        this.secretKey = AESUtil.generateKey();
//        logger.debug(String.format("The initial position of user [%s's] enigma is set to [%d, %d, %d]",
//                name, idx1, idx2, idx3));

        byte[] rBytes = new byte[16];
        new SecureRandom().nextBytes(rBytes);
        r = new BigInteger(rBytes);
        logger.debug("The 128-bit random bit integer [{}]", r);
    }

    public static void main(String[] args) {
        Config.init();
        User user = new User(args[0].trim(), Config.getAlphabets(), Config.getPositions());
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
        d1Str = encryptMachine.encode(key);
        d2Str = encryptMachine.encode(key);
        logger.debug(String.format("[%s's] key is [%s], d1 string is [%s], d2 string is [%s]",
                name, key, d1Str, d2Str));
    }

    @NotNull
    public BigInteger addD1WithR(@NotNull BigInteger start) {
        BigInteger add = start.add(getDWithR(d1Str));
        logger.debug(String.format("%s accept X[%s], return X[%s]", name, start, add));
        return add;
    }

    @NotNull
    public BigInteger addD2WithR(@NotNull BigInteger start) {
        BigInteger add = start.add(getDWithR(d2Str));
        logger.debug(String.format("%s accept X[%s], return X[%s]", name, start, add));
        return add;
    }

    @NotNull
    public BigInteger getDWithR(@NotNull String dString) {
        BigInteger d = new BigInteger(dString.getBytes());
        return r.add(d);
    }
}
