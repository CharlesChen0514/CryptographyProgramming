package org.bitkernel.cryptography;

import com.sun.istack.internal.NotNull;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtil {
    private static final Cipher cipher;
    private static final KeyFactory factory;

    static {
        try {
            cipher = Cipher.getInstance("RSA");
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public static <T extends Key> byte[] encrypt(@NotNull byte[] plainData, @NotNull T key) {
        try {
            // 初始化密码器（公钥加密模型）
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // 加密数据, 返回加密后的密文
            return cipher.doFinal(plainData);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public static <T extends Key> byte[] decrypt(@NotNull byte[] cipherData, @NotNull T key) {
        try {
            // 初始化密码器（私钥解密模型）
            cipher.init(Cipher.DECRYPT_MODE, key);
            // 解密数据, 返回解密后的明文
            return cipher.doFinal(cipherData);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public static PublicKey getPublicKey(@NotNull String pubKeyBase64) {
        try {
            // 把 公钥的Base64文本 转换为已编码的 公钥bytes
            byte[] encPubKey = new BASE64Decoder().decodeBuffer(pubKeyBase64);
            // 创建 已编码的公钥规格
            X509EncodedKeySpec encPubKeySpec = new X509EncodedKeySpec(encPubKey);
            // 获取指定算法的密钥工厂, 根据 已编码的公钥规格, 生成公钥对象
            return factory.generatePublic(encPubKeySpec);
        } catch (InvalidKeySpecException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public static PrivateKey getPrivateKey(@NotNull String priKeyBase64) {
        try {
            // 把 私钥的Base64文本 转换为已编码的 私钥bytes
            byte[] encPriKey = new BASE64Decoder().decodeBuffer(priKeyBase64);
            // 创建 已编码的私钥规格
            PKCS8EncodedKeySpec encPriKeySpec = new PKCS8EncodedKeySpec(encPriKey);
            // 获取指定算法的密钥工厂, 根据 已编码的私钥规格, 生成私钥对象
            return factory.generatePrivate(encPriKeySpec);
        } catch (InvalidKeySpecException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    public static String getKeyEncodedBase64(@NotNull Key key) {
        // 获取密钥编码后的格式
        byte[] encBytes = key.getEncoded();
        // 转换为 Base64 文本
        return new BASE64Encoder().encode(encBytes);
    }
}
