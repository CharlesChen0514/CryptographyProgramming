import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Letter;
import org.bitkernel.signserver.SignRequest;

import java.security.PublicKey;

@Slf4j
public class Scenario2 extends Scenario1 {
    public static void main(String[] args) throws InterruptedException {
        Scenario1.runTest();
        Scenario2.runTest();
    }

    protected static void runTest() throws InterruptedException {
        System.out.println();
        logger.debug("-----------------------Step 5: co-signature---------------------------------");
        PublicKey rsaPubKey = signServer.getRSAPubKey();
        signServer.register(alice.getName(), alice.getSecretKey(rsaPubKey));
        signServer.register(bob.getName(), bob.getSecretKey(rsaPubKey));

        signServer.newSignRequest(alice.getName(), alice.generateSignReq(groupTag, "hello"), storageGateway);
        logger.debug("Simulate user {} is offline, sleep 2 seconds", bob.getName());
        Thread.sleep(2000);
        logger.debug("{} is online", bob.getName());
        SignRequest signReq = signServer.authorized(bob.getName(), bob.generateAuthorizedReq(groupTag), storageGateway);

        Letter letter = signReq.getLetter();
        blockChainSystem.acceptLetter(letter);
    }
}
