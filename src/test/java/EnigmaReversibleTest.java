import lombok.extern.slf4j.Slf4j;
import org.bitkernel.enigma.Enigma;
import org.bitkernel.enigma.Message;
import org.bitkernel.User;

@Slf4j
public class EnigmaReversibleTest {
    public static void main(String[] args) {
        User alice = new User("alice");
        alice.generateEncryptedNumber("hellolll");

        Enigma decodeMachine = new Enigma();
        Message d1Message = alice.getD1Message();
        String key1 = decodeMachine.decode(d1Message);
        logger.info("The key decrypted from d1 is [{}]", key1);

        Message d2Message = alice.getD2Message();
        String key2 = decodeMachine.decode(d2Message);
        logger.info("The key decrypted from d2 is [{}]", key2);
    }
}
