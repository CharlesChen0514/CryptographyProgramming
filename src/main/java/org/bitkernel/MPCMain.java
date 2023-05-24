package org.bitkernel;

import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
public class MPCMain {

    @NotNull
    public List<Integer> generatePath(int size) {
        List<Integer> path = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            path.add(i);
        }
        Collections.shuffle(path);
        return path;
    }

    @NotNull
    public BigInteger getSumD(@NotNull BigInteger x, @NotNull BigInteger... rValues) {
        BigInteger sumD = new BigInteger(x.toByteArray());
        for (BigInteger r : rValues) {
            sumD = sumD.subtract(r);
        }
        return sumD;
    }

    @NotNull
    public String generateGroupTag(@NotNull User[] users) {
        StringBuilder sb = new StringBuilder();
        for (User user: users) {
            sb.append(user.getName()).append("@");
        }
        return sb.toString();
    }

    @NotNull
    public Pair<byte[], byte[]> generateRSAKeyPair(@NotNull BigInteger d1Sum,
                                                   @NotNull BigInteger d2Sum) {
        // TODO: 基于 GMP 库实现
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed("random seed value".getBytes());
        // 初始化密钥对生成器，并设置密钥长度为 1024 位
        keyPairGenerator.initialize(1024, secureRandom);

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 获取公钥和私钥
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();
        return new Pair<>(new BigInteger(publicKeyBytes).abs().toByteArray(),
                new BigInteger(privateKeyBytes).abs().toByteArray());
    }

    private byte[] removeLeadingZero(byte[] bytes) {
        if (bytes[0] != 0) {
            return bytes;
        } else {
            byte[] result = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, result, 0, result.length);
            return result;
        }
    }

    @NotNull
    public static BigInteger dataPadding(@NotNull BigInteger data) {
        byte[] input = data.toByteArray();
        if (input.length != Constant.R_BYTE_NUM) {
            logger.error("Input error, the byte length {} is not as expected {}",
                    input.length, Constant.R_BYTE_NUM);
            return BigInteger.ZERO;
        }
        byte[] output = new byte[Constant.RSA_BYTE_NUM];
        int factor = output.length / input.length;
        for (int i = 0; i < input.length; i++) {
            output[i * factor] = input[i];
        }
        return new BigInteger(output);
    }

    public static void main(String[] args) {
        byte[] input = new byte[16];
        new SecureRandom().nextBytes(input);
        BigInteger bigInteger = dataPadding(new BigInteger(input));
        System.out.println(bigInteger);
    }
}
