import lombok.extern.slf4j.Slf4j;
import org.bitkernel.enigma.Enigma;
import org.bitkernel.User;

@Slf4j
public class Scenario1EnigmaReversibleTest {
    public static void main(String[] args) {
        User alice = new User("alice");
        alice.generateEncryptedNumber("hellolll");

        int[] ps = {0, 1, 2};
        Enigma decodeMachine = new Enigma("abcdefghijklmnopqrstuvwxyz", ps);
        String d1Message = alice.getD1Str();
        String key1 = decodeMachine.decode(d1Message);
        logger.info("The key decrypted from d1 is [{}]", key1);

        String d2Message = alice.getD2Str();
        String key2 = decodeMachine.decode(d2Message);
        logger.info("The key decrypted from d2 is [{}]", key2);
    }
}
