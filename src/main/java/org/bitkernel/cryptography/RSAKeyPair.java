package org.bitkernel.cryptography;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Slf4j
public class RSAKeyPair {
    private BigInteger publicKeyExponent;
    private BigInteger privateKeyExponent;
    private BigInteger modulus;
    @Getter
    private PublicKey publicKey;
    @Getter
    private PrivateKey privateKey;

    public RSAKeyPair(@NotNull BigInteger p, @NotNull BigInteger q) {
        generateKeyPair(p, q);
    }

    public RSAKeyPair() {
        BigInteger p = generateRandomPrime(1024);
        BigInteger q = generateRandomPrime(1024);
        generateKeyPair(p, q);
    }

    private void generateKeyPair(@NotNull BigInteger p, @NotNull BigInteger q) {
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

        String pubKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(rsAKeyPair.getPublicKey());
        PublicKey publicKey = RSAUtil.getPublicKey(pubKeyEncodedBase64);
        if (publicKey.toString().equals(rsAKeyPair.getPublicKey().toString())) {
            System.out.println("The recover public key is equal");
        }

        String priKeyEncodedBase64 = RSAUtil.getKeyEncodedBase64(rsAKeyPair.getPrivateKey());
        PrivateKey priKey = RSAUtil.getPrivateKey(priKeyEncodedBase64);
        if (priKey.toString().equals(rsAKeyPair.getPrivateKey().toString())) {
            System.out.println("The recover private key is equal");
        }
    }
}
