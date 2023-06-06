package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.bitkernel.cryptography.RSAUtil;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

@AllArgsConstructor
public class Letter {
    @Getter
    @Setter
    private List<String> messages;
    @Getter
    private byte[] signature;
    @Getter
    private PublicKey publicKey;

    @Override
    public String toString() {
        String[] strArr = new String[3];
        strArr[0] = StringUtils.join(messages, ":");
        strArr[1] = Arrays.toString(signature);
        strArr[2] = RSAUtil.getKeyEncodedBase64(publicKey);
        return StringUtils.join(strArr, "@");
    }

    @NotNull
    private static byte[] StringToByteArray(@NotNull String str) {
        String[] strArray = str.replaceAll("[\\[\\]\\s]", "").split(",");
        byte[] byteArray = new byte[strArray.length];
        for (int i = 0; i < strArray.length; i++) {
            byteArray[i] = Byte.parseByte(strArray[i]);
        }
        return byteArray;
    }

    @NotNull
    public static Letter parse(@NotNull String str) {
        String[] split = str.split("@");
        String[] messageArr = split[0].split(":");
        List<String> messageList = Arrays.asList(messageArr);
        byte[] signature = StringToByteArray(split[1]);
        PublicKey publicKey = RSAUtil.getPublicKey(split[2]);
        return new Letter(messageList, signature, publicKey);
    }
}
