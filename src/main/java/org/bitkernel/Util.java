package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class Util {
    @NotNull
    public static byte[] stringToByteArray(@NotNull String str) {
        String[] strArray = str.replaceAll("[\\[\\]\\s]", "").split(",");
        byte[] byteArray = new byte[strArray.length];
        for (int i = 0; i < strArray.length; i++) {
            byteArray[i] = Byte.parseByte(strArray[i]);
        }
        return byteArray;
    }

    public static MessageDigest getMessageDigestInstance() {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage());
        }
        return md;
    }
}
