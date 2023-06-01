import lombok.extern.slf4j.Slf4j;
import org.bitkernel.User;
import org.bitkernel.cryptography.RSAKeyPair;
import org.bitkernel.cryptography.RSAUtil;

import java.math.BigInteger;
import java.util.List;
import java.util.Scanner;

@Slf4j
public class Scenario3 extends Scenario1 {
    public static void main(String[] args) throws InterruptedException {
        Scenario1.runTest();
        Scenario3.runTest();
    }

    protected static void runTest() {
        logger.error("Storage provider has malfunctioned");
        storageGateway.randomDestroyProvider();
        storageGateway.randomDestroyProvider();

        System.out.println("Please follow the instructions below to recover the RSA key");
        Scanner in = new Scanner(System.in);

        System.out.print("Alice, please input the key: ");
        String aliceKey = in.next();
//        String aliceKey = "abcdefgh";

        System.out.print("Bob, please input the key: ");
        String bobKey = in.next();
//        String bobKey = "ijklmnop";

        User alice1 = new User("alice");
        User bob1 = new User("bob");
        User[] group1 = new User[] {alice1, bob1};

        logger.debug("-----------------------Step 1: get encrypted number-----------------------");
        alice1.generateEncryptedNumber(aliceKey);
        bob1.generateEncryptedNumber(bobKey);

        System.out.println();
        logger.debug("-----------------------Step 2: get base D----------------------------------");
        List<Integer> path = mpcMain.generatePath(group1);
        BigInteger sumD1WithSalt = getSumD1WithSalt(path, group1);
        BigInteger sumD2WithSalt = getSumD2WithSalt(path, group1);
        BigInteger sumD1 = mpcMain.getSumD(sumD1WithSalt, alice1.getR(), bob1.getR());
        BigInteger sumD2 = mpcMain.getSumD(sumD2WithSalt, alice1.getR(), bob1.getR());
        logger.debug("Sum D1 is [{}]", sumD1);
        logger.debug("Sum D2 is [{}]", sumD2);

        System.out.println();
        logger.debug("-----------------------Step 3: generate RSA keys----------------------------");
        RSAKeyPair keyPair = mpcMain.generateRSAKeyPair(sumD1, sumD2);
        logger.debug("\nThe public key is {}", RSAUtil.getKeyEncodedBase64(keyPair.getPublicKey()));
        logger.debug("\nThe private key is {}", RSAUtil.getKeyEncodedBase64(keyPair.getPrivateKey()));

        System.out.println();
        logger.debug("-----------------------Step 4: data recovering----------------------------");
        String groupTag = mpcMain.generateGroupTag(group1);
        boolean check = storageGateway.checkRecover(group1, groupTag, keyPair);
        if (check) {
            storageGateway.store(group1, groupTag, keyPair);
            logger.debug("RSA key recover success");
        } else {
            logger.error("RSA key recover failed, please insure the key is correct");
        }
    }
}
