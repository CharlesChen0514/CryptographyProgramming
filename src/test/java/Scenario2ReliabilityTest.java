import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Letter;
import org.bitkernel.rsa.RSAUtil;
import org.bitkernel.signserver.SignRequest;

import java.security.PublicKey;

@Slf4j
public class Scenario2ReliabilityTest extends Scenario1 {

    public static void main(String[] args) throws InterruptedException {
        Scenario1.runTest();
        Scenario2ReliabilityTest.runTest();
    }

    protected static void runTest() {
        System.out.println();
        logger.debug("-----------------------Step 5: co-signature---------------------------------");
        storageGateway.randomDestroyProvider();
        PublicKey rsaPubKey = signServer.getRSAPubKey();
        String signReqString = String.format("%s-%s-%s", alice.getName(), groupTag, "hello");
        byte[] encrypt = RSAUtil.encrypt(signReqString.getBytes(), rsaPubKey);
        signServer.newSignRequest(encrypt, storageGateway);

        String authorizedString = String.format("%s-%s", bob.getName(), groupTag);
        encrypt = RSAUtil.encrypt(authorizedString.getBytes(), rsaPubKey);
        SignRequest signReq = signServer.authorized(encrypt, storageGateway, blockChainSystem);
        Letter letter = signReq.getLetter();
        blockChainSystem.acceptLetter(letter);
    }
}
