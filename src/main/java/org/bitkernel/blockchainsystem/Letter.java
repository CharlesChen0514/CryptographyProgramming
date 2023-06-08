package org.bitkernel.blockchainsystem;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.bitkernel.cryptography.RSAUtil;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@AllArgsConstructor
public class Letter {
    @Getter
    @Setter
    private Map<String, String> messageMap;
    @Getter
    private byte[] signature;
    @Getter
    private PublicKey publicKey;

    @Override
    public String toString() {
        String[] strArr = new String[4];
        strArr[0] = StringUtils.join(messageMap.keySet(), ":");
        strArr[1] = StringUtils.join(messageMap.values(), ":");
        strArr[2] = Arrays.toString(signature);
        strArr[3] = RSAUtil.getKeyEncodedBase64(publicKey);
        return StringUtils.join(strArr, "@");
    }

    @NotNull
    private static byte[] stringToByteArray(@NotNull String str) {
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
        List<String> userList = Arrays.asList(split[0].split(":"));
        List<String> messageList = Arrays.asList(split[1].split(":"));
        Map<String, String> messageMap = new LinkedHashMap<>();
        for (int i = 0; i < userList.size(); i++) {
            messageMap.put(userList.get(i), messageList.get(i));
        }
        byte[] signature = stringToByteArray(split[2]);
        PublicKey publicKey = RSAUtil.getPublicKey(split[3]);
        return new Letter(messageMap, signature, publicKey);
    }
}
