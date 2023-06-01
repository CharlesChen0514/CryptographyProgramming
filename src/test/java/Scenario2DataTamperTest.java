import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Letter;
import org.bitkernel.signserver.SignRequest;

import java.security.PublicKey;

@Slf4j
public class Scenario2DataTamperTest extends Scenario1 {

    public static void main(String[] args) throws InterruptedException {
        Scenario1.runTest();
        Scenario2DataTamperTest.runTest();
    }

    public static void runTest() {
        System.out.println();
        logger.debug("-----------------------Step 5: co-signature---------------------------------");
        PublicKey rsaPubKey = signServer.getRSAPubKey();
        signServer.register(alice.getName(), alice.getSecretKey(rsaPubKey));
        signServer.register(bob.getName(), bob.getSecretKey(rsaPubKey));

        signServer.newSignRequest(alice.getName(), alice.generateSignReq(groupTag, "hello"), storageGateway);
        SignRequest signReq = signServer.authorized(bob.getName(), bob.generateAuthorizedReq(groupTag), storageGateway);
        Letter letter = signReq.getLetter();

        // simulated data tampering
        String msgTamper = "nihao";
        logger.error("The letter message [{}] is tamper to [{}]", letter.getMsg(), msgTamper);
        letter.setMsg(msgTamper);
        blockChainSystem.acceptLetter(letter);
    }
}
