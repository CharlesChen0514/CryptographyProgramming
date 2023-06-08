package org.bitkernel.blockchainsystem;

import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Util;
import org.bitkernel.common.Config;
import org.bitkernel.common.Udp;
import org.bitkernel.cryptography.RSAUtil;

import java.security.MessageDigest;

@Slf4j
public class BlockChainSystem {
    private final Udp udp;

    public BlockChainSystem() {
        udp = new Udp(Config.getBlockChainSysPort());
    }

    public static void main(String[] args) {
        BlockChainSystem blockChainSystem = new BlockChainSystem();
        blockChainSystem.run();
    }

    public void run() {
        logger.debug("Block chain system start success");
        while (true) {
            String letterString = udp.receiveString();
            Letter letter = Letter.parse(letterString);
            logger.debug("Receive a letter");

            byte[] hash1 = RSAUtil.decrypt(letter.getSignature(), letter.getPublicKey());
            String hash1Str = new String(hash1);
            logger.debug("Get hash1 by decrypting the signature with the public key: {}", hash1Str);

            MessageDigest md = Util.getMessageDigestInstance();
            byte[] hash2 = md.digest(letter.getMessageMap().toString().getBytes());
            String hash2Str = new String(hash2);
            logger.debug("Get hash2 by computing the digital abstract of the message: {}", hash2Str);
            if (hash1Str.equals(hash2Str)) {
                logger.debug("Letter data has not been tampered");
            } else {
                logger.error("Letter data has been tampered");
            }
        }
    }
}
