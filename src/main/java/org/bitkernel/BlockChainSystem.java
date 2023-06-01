package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.cryptography.RSAUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class BlockChainSystem {

    public static MessageDigest getMessageDigestInstance() {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage());
        }
        return md;
    }

    public void acceptLetter(@NotNull Letter letter) {
        byte[] hash1 = RSAUtil.decrypt(letter.getSignature(), letter.getPublicKey());
        String hash1Str = new String(hash1);
        logger.debug("Get hash1 by decrypting the signature with the public key: {}", hash1Str);

        MessageDigest md = getMessageDigestInstance();
        byte[] hash2 = md.digest(letter.getMsg().getBytes());
        String hash2Str = new String(hash2);
        logger.debug("Get hash2 by computing the digital abstract of the message: {}", hash2Str);
        if (hash1Str.equals(hash2Str)) {
            logger.debug("Letter data has not been tampered");
        } else {
            logger.error("Letter data has been tampered");
        }
    }
}
