import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.*;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.List;

@Slf4j
public class Scenario1 {
    private static final User alice = new User("alice");
    private static final User bob = new User("bob");
    private static final User[] group = {alice, bob};
    private static final MPCMain mpcMain = new MPCMain();
    private static final StorageGateway storageGateway = new StorageGateway();
    private static final SignServer signServer = new SignServer();
    private static final BlockChainSystem blockChainSystem = new BlockChainSystem();

    public static void main(String[] args) {
        logger.debug("-----------------------Step 1: get encrypted number-----------------------");
        alice.generateEncryption("abcdefgh");
        bob.generateEncryption("ijklmnop");
        logger.debug("-----------------------Step 1: get encrypted number done-------------------");

        logger.debug("-----------------------Step 2: get base D----------------------------------");
        List<Integer> path = mpcMain.generatePath(group.length);
        printPath(path, group);
        BigInteger sumD1WithSalt = getSumD1WithSalt(path, group);
        BigInteger sumD2WithSalt = getSumD2WithSalt(path, group);
        BigInteger sumD1 = mpcMain.getSumD(sumD1WithSalt, alice.getR(), bob.getR());
        BigInteger sumD2 = mpcMain.getSumD(sumD2WithSalt, alice.getR(), bob.getR());
        logger.debug("Sum D1 is {}", sumD1);
        logger.debug("Sum D2 is {}", sumD2);
        logger.debug("-----------------------Step 2: get base D done------------------------------");

        logger.debug("-----------------------Step 3: generate RSA keys----------------------------");
        String groupTag = mpcMain.generateGroupTag(group);
        logger.debug("The group tag is {}", groupTag);
        RSAKeyPair keyPair = mpcMain.generateRSAKeyPair(sumD1, sumD2);
        logger.debug("The public key is {}", keyPair.getPublicKey().getEncoded());
        logger.debug("The private key is {}", keyPair.getPrivateKey().getEncoded());
        logger.debug("-----------------------Step 3: generate RSA keys done-----------------------");

        logger.debug("-----------------------Step 4: reliable storage-----------------------------");
        storageGateway.store(group, groupTag, keyPair);
//        byte[] subPriKey = storageGateway.getSubPriKey(alice.getName(), groupTag);
//        byte[] bytes = storageGateway.getUserSubPriKeyMap().get(alice.getName()).get(groupTag);
//        if (new String(subPriKey).equals(new String(bytes))) {
//            logger.debug("success");
//        }
//        PublicKey pubKey = storageGateway.getPubKey(groupTag);
//        if (pubKey.toString().equals(storageGateway.getPublicKeyMap().get(groupTag).toString())) {
//            logger.debug("public key success");
//        }
        logger.debug("-----------------------Step 4: reliable storage done------------------------");

        logger.debug("-----------------------Step 5: co-signature---------------------------------");
        PublicKey rsaPubKey = signServer.getRSAPubKey();
        String signReqString = String.format("%s-%s-%s", alice.getName(), groupTag, "hello");
        byte[] encrypt = RSAUtil.encrypt(signReqString.getBytes(StandardCharsets.UTF_8), rsaPubKey);
        signServer.newSignRequest(encrypt, storageGateway);

        String authorizedString = String.format("%s-%s", bob.getName(), groupTag);
        encrypt = RSAUtil.encrypt(authorizedString.getBytes(StandardCharsets.UTF_8), rsaPubKey);
        signServer.authorized(encrypt, storageGateway);
        logger.debug("-----------------------Step 5: co-signature done----------------------------");
    }

    @NotNull
    public static void printPath(@NotNull List<Integer> path, @NotNull User[] group) {
        StringBuilder sb = new StringBuilder();
        for (int idx : path) {
            User user = group[idx];
            sb.append(user.getName()).append("->");
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);
        logger.debug("Transfer path: {}", sb);
    }

    @NotNull
    public static BigInteger getSumD1WithSalt(@NotNull List<Integer> path, @NotNull User[] group) {
        BigInteger x1 = BigInteger.ZERO;
        for (int idx : path) {
            User user = group[idx];
            x1 = user.addD1WithR(x1);
        }
        logger.debug("The aggregated value of all users d1 and R is {}", x1);
        return x1;
    }

    @NotNull
    public static BigInteger getSumD2WithSalt(@NotNull List<Integer> path, @NotNull User[] group) {
        BigInteger x2 = BigInteger.ZERO;
        for (int idx : path) {
            User user = group[idx];
            x2 = user.addD2WithR(x2);
        }
        logger.debug("The aggregated value of all users d2 and R is {}", x2);
        return x2;
    }
}
