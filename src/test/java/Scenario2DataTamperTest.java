import lombok.extern.slf4j.Slf4j;
import org.bitkernel.Letter;
import org.bitkernel.rsa.RSAUtil;
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
        String signReqString = String.format("%s-%s-%s", alice.getName(), groupTag, "hello");
        byte[] encrypt = RSAUtil.encrypt(signReqString.getBytes(), rsaPubKey);
        signServer.newSignRequest(encrypt, storageGateway);

        String authorizedString = String.format("%s-%s", bob.getName(), groupTag);
        encrypt = RSAUtil.encrypt(authorizedString.getBytes(), rsaPubKey);
        SignRequest signReq = signServer.authorized(encrypt, storageGateway);
        Letter letter = signReq.getLetter();
        // simulated data tampering
        String msgTamper = "nihao";
        logger.error("The letter message [{}] is tamper to [{}]", letter.getMsg(), msgTamper);
        letter.setMsg(msgTamper);
        blockChainSystem.acceptLetter(letter);
    }
}
