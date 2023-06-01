import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Letter;
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
        signServer.register(alice.getName(), alice.getSecretKey(rsaPubKey));
        signServer.register(bob.getName(), bob.getSecretKey(rsaPubKey));

        signServer.newSignRequest(alice.getName(), alice.generateSignReq(groupTag, "hello"), storageGateway);
        SignRequest signReq = signServer.authorized(bob.getName(), bob.generateAuthorizedReq(groupTag), storageGateway);

        Letter letter = signReq.getLetter();
        blockChainSystem.acceptLetter(letter);
    }
}
