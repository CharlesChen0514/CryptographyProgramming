import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.*;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;
import org.bitkernel.signserver.SignServer;

import java.math.BigInteger;
import java.util.List;

@Slf4j
public class Scenario1 {
    protected static final User alice = new User("alice");
    protected static final User bob = new User("bob");
    protected static final User[] group = {alice, bob};
    protected static String groupTag;
    protected static final MPCMain mpcMain = new MPCMain();
    protected static final StorageGateway storageGateway = new StorageGateway();
    protected static final SignServer signServer = new SignServer();
    protected static final BlockChainSystem blockChainSystem = new BlockChainSystem();

    public static void main(String[] args) throws InterruptedException {
        runTest();
    }

    protected static void runTest() throws InterruptedException {
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
        RSAKeyPair keyPair = mpcMain.generateRSAKeyPair(sumD1, sumD2);
        logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(keyPair.getPublicKey()));
        logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(keyPair.getPrivateKey()));

        System.out.println();
        logger.debug("-----------------------Step 4: reliable storage-----------------------------");
        groupTag = mpcMain.generateGroupTag(group);
        storageGateway.store(group, groupTag, keyPair);
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
