package org.bitkernel.cryptography;

import com.sun.istack.internal.NotNull;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class AESUtil {
    private static final Cipher cipher;
    private static final KeyGenerator keyGenerator;

    static {
        try {
            cipher = Cipher.getInstance("AES");
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey generateKey() {
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    @NotNull
    public static <T extends Key> byte[] encrypt(@NotNull byte[] plainData, @NotNull T key) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainData);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public static <T extends Key> byte[] decrypt(@NotNull byte[] cipherData, @NotNull T key) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(cipherData);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
