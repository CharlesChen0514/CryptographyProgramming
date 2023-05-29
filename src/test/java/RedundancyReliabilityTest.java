import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.*;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;

@Slf4j
public class RedundancyReliabilityTest {
    private static final User alice = new User("alice");
    private static final User bob = new User("bob");
    private static final User[] group = {alice, bob};
    private static final MPCMain mpcMain = new MPCMain();
    private static final StorageGateway storageGateway = new StorageGateway();
    private static final SignServer signServer = new SignServer();
    private static final BlockChainSystem blockChainSystem = new BlockChainSystem();

    public static void main(String[] args) throws InterruptedException {
        System.out.println();
        logger.debug("-----------------------Step 1: get encrypted number-----------------------");
        alice.generateEncryptedNumber("abcdefgh");
        bob.generateEncryptedNumber("ijklmnop");

        System.out.println();
        logger.debug("-----------------------Step 2: get base D----------------------------------");
        List<Integer> path = mpcMain.generatePath(group);
        BigInteger sumD1WithSalt = getSumD1WithSalt(path, group);
        BigInteger sumD2WithSalt = getSumD2WithSalt(path, group);
        BigInteger sumD1 = mpcMain.getSumD(sumD1WithSalt, alice.getR(), bob.getR());
        BigInteger sumD2 = mpcMain.getSumD(sumD2WithSalt, alice.getR(), bob.getR());
        logger.debug("Sum D1 is [{}]", sumD1);
        logger.debug("Sum D2 is [{}]", sumD2);

        System.out.println();
        logger.debug("-----------------------Step 3: generate RSA keys----------------------------");
        String groupTag = mpcMain.generateGroupTag(group);
        RSAKeyPair keyPair = mpcMain.generateRSAKeyPair(sumD1, sumD2);
        logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(keyPair.getPublicKey()));
        logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(keyPair.getPrivateKey()));

        System.out.println();
        logger.debug("-----------------------Step 4: reliable storage-----------------------------");
        storageGateway.store(group, groupTag, keyPair);

        System.out.println();
        logger.debug("-----------------------Step 5: co-signature---------------------------------");
        storageGateway.randomDestroyProvider();
        PublicKey rsaPubKey = signServer.getRSAPubKey();
        String signReqString = String.format("%s-%s-%s", alice.getName(), groupTag, "hello");
        byte[] encrypt = RSAUtil.encrypt(signReqString.getBytes(), rsaPubKey);
        signServer.newSignRequest(encrypt, storageGateway);

        logger.debug("{} is offline", bob.getName());
        Thread.sleep(2000);
        logger.debug("{} is online", bob.getName());

        String authorizedString = String.format("%s-%s", bob.getName(), groupTag);
        encrypt = RSAUtil.encrypt(authorizedString.getBytes(), rsaPubKey);
        signServer.authorized(encrypt, storageGateway, blockChainSystem);
    }

    @NotNull
    public static BigInteger getSumD1WithSalt(@NotNull List<Integer> path,
                                              @NotNull User[] group) {
        BigInteger x1 = BigInteger.ZERO;
        for (int idx : path) {
            User user = group[idx];
            x1 = user.addD1WithR(x1);
        }
        logger.debug("The aggregated value of all users d1 and R is [{}]", x1);
        return x1;
    }

    @NotNull
    public static BigInteger getSumD2WithSalt(@NotNull List<Integer> path,
                                              @NotNull User[] group) {
        BigInteger x2 = BigInteger.ZERO;
        for (int idx : path) {
            User user = group[idx];
            x2 = user.addD2WithR(x2);
        }
        logger.debug("The aggregated value of all users d2 and R is [{}]", x2);
        return x2;
    }
}
