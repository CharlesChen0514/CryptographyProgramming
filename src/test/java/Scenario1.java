import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.MPCMain;
import org.bitkernel.User;

import java.math.BigInteger;
import java.util.List;

@Slf4j
public class Scenario1 {
    public static void main(String[] args) {
        User alice = new User("alice");
        alice.generateEncryption("abcdefgh");

        User bob = new User("bob");
        bob.generateEncryption("ijklmnop");

        MPCMain main = new MPCMain();
        User[] group = {alice, bob};
        List<Integer> path = main.generatePath(group.length);
        printPath(path, group);
        BigInteger sumD1WithSalt = getSumD1WithSalt(path, group);
        BigInteger sumD2WithSalt = getSumD2WithSalt(path, group);
        BigInteger sumD1 = main.getSumD(sumD1WithSalt, alice.getR(), bob.getR());
        BigInteger sumD2 = main.getSumD(sumD2WithSalt, alice.getR(), bob.getR());
        logger.debug("Sum D1 is {}", sumD1);
        logger.debug("Sum D2 is {}", sumD2);
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
        logger.debug("The aggregated value of all users d1 and R is {}", x2);
        return x2;
    }
}
