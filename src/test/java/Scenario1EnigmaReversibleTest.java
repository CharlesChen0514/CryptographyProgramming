import lombok.extern.slf4j.Slf4j;
import org.bitkernel.enigma.Enigma;
import org.bitkernel.enigma.EnigmaMessage;
import org.bitkernel.User;

@Slf4j
public class Scenario1EnigmaReversibleTest {
    public static void main(String[] args) {
        User alice = new User("alice");
        alice.generateEncryptedNumber("hellolll");

        Enigma decodeMachine = new Enigma();
        EnigmaMessage d1Message = alice.getD1();
        String key1 = decodeMachine.decode(d1Message);
        logger.info("The key decrypted from d1 is [{}]", key1);

        EnigmaMessage d2Message = alice.getD2();
        String key2 = decodeMachine.decode(d2Message);
        logger.info("The key decrypted from d2 is [{}]", key2);
    }
}
