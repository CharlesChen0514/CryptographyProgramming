import lombok.extern.slf4j.Slf4j;
import org.bitkernel.User;

@Slf4j
public class Scenario1 {
    public static void main(String[] args) {
        User alice = new User("alice");
        alice.generateEncryption("abcdefgh");

        User bob = new User("bob");
        bob.generateEncryption("ijklmnop");
    }
}
