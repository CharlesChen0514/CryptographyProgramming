package org.bitkernel.rsa;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import sun.misc.BASE64Encoder;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Slf4j
public class RSAKeyPair {
    private final BigInteger publicKeyExponent;
    private final BigInteger privateKeyExponent;
    private final BigInteger modulus;
    @Getter
    private final PublicKey publicKey;
    @Getter
    private final PrivateKey privateKey;
    public RSAKeyPair(@NotNull BigInteger p, @NotNull BigInteger q) {
        BigInteger one = BigInteger.ONE;
        modulus = p.multiply(q);
        BigInteger phi = p.subtract(one).multiply(q.subtract(one));

        publicKeyExponent = new BigInteger("65537"); // Commonly used public exponent
        privateKeyExponent = publicKeyExponent.modInverse(phi);

        // 生成公钥
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicKeyExponent);
            publicKey = keyFactory.generatePublic(publicKeySpec);

            // 生成私钥
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateKeyExponent);
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public String getPriKeyEncodedBase64() {
        // 获取密钥编码后的格式
        byte[] encBytes = privateKey.getEncoded();
        // 转换为 Base64 文本
        return new BASE64Encoder().encode(encBytes);
    }

    @NotNull
    public String getPubKeyEncodedBase64() {
        // 获取密钥编码后的格式
        byte[] encBytes = publicKey.getEncoded();
        // 转换为 Base64 文本
        return new BASE64Encoder().encode(encBytes);
    }

    // 生成一个指定位数的素数
    private static BigInteger generateRandomPrime(int bits) {
        BigInteger p = BigInteger.probablePrime(bits, new SecureRandom());
        while (!p.isProbablePrime(100)) {
            p = p.add(BigInteger.valueOf(2));
        }
        return p;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger P = generateRandomPrime(512);
        BigInteger Q = generateRandomPrime(512);
        RSAKeyPair rsAKeyPair = new RSAKeyPair(P, Q);

        // 输出生成的密钥对
        System.out.println("Public Key: " + rsAKeyPair.getPublicKey());
        System.out.println("Private Key: " + rsAKeyPair.getPrivateKey());

        String pubKeyEncodedBase64 = rsAKeyPair.getPubKeyEncodedBase64();
        PublicKey publicKey = RSAUtil.getPublicKey(pubKeyEncodedBase64);
        if (publicKey.toString().equals(rsAKeyPair.getPublicKey().toString())) {
            System.out.println("The recover public key is equal");
        }

        String priKeyEncodedBase64 = rsAKeyPair.getPriKeyEncodedBase64();
        PrivateKey priKey = RSAUtil.getPrivateKey(priKeyEncodedBase64);
        if (priKey.toString().equals(rsAKeyPair.getPrivateKey().toString())) {
            System.out.println("The recover private key is equal");
        }
    }
}
