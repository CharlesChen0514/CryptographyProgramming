package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.cryptography.RSAKeyPair;

import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
public class MPCMain {
    public static final int R_BYTE_NUM = 16;
    public static final int RSA_BYTE_NUM = 128;

    /**
     * generate the message transfer path randomly
     * @param users user group
     * @return transfer path, e.g. [2, 1, 3] : 2 -> 1 -> 3
     */
    @NotNull
    public List<Integer> generatePath(@NotNull User[] users) {
        List<Integer> path = new ArrayList<>();
        for (int i = 0; i < users.length; i++) {
            path.add(i);
        }
        Collections.shuffle(path);
        printPath(path, users);
        return path;
    }

    /**
     * Print the transfer path by name
     * @param path the transfer path by index
     */
    @NotNull
    public static void printPath(@NotNull List<Integer> path,
                                 @NotNull User[] group) {
        StringBuilder sb = new StringBuilder();
        for (int idx : path) {
            User user = group[idx];
            sb.append(user.getName()).append("->");
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);
        logger.debug("The SMPC transfer path is: {}", sb);
    }

    /**
     *
     * @param x the aggregate value by D and R
     * @param rValues R value list
     * @return the sum of D
     */
    @NotNull
    public BigInteger getSumD(@NotNull BigInteger x,
                              @NotNull BigInteger... rValues) {
        BigInteger sumD = new BigInteger(x.toByteArray());
        for (BigInteger r : rValues) {
            sumD = sumD.subtract(r);
        }
        return sumD;
    }

    /**
     * Join all username by '@' to generate a group tag
     * @return group tag
     */
    @NotNull
    public String generateGroupTag(@NotNull User[] users) {
        StringBuilder sb = new StringBuilder();
        sb.append(users.length).append("@");
        for (User user: users) {
            sb.append(user.getName()).append("@");
        }
        sb.deleteCharAt(sb.length() - 1);
        logger.debug("Generate a group tag is {}", sb);
        return sb.toString();
    }

    /**
     * Base on the d1 sum and d2 sum to generate the RSA key pair
     */
    @NotNull
    public RSAKeyPair generateRSAKeyPair(@NotNull BigInteger d1Sum,
                                         @NotNull BigInteger d2Sum) {
        BigInteger d1SumPadding = dataPadding(d1Sum);
        BigInteger d2SumPadding = dataPadding(d2Sum);
        logger.debug("D1 sum [{}] expanding to [{}]", d1Sum, d1SumPadding);
        logger.debug("D2 sum [{}] expanding to [{}]", d2Sum, d2SumPadding);
        BigInteger p = findNextPrime(d1SumPadding);
        BigInteger q = findNextPrime(d2SumPadding);
        logger.debug("Find P [{}]", p);
        logger.debug("Find Q [{}]", q);
        return new RSAKeyPair(p, q);
    }

    @NotNull
    private BigInteger findNextPrime(@NotNull BigInteger base) {
        while (!base.isProbablePrime(1024)) {
            base = base.add(BigInteger.ONE);
        }
        return base;
    }

    @NotNull
    public static BigInteger dataPadding(@NotNull BigInteger data) {
        byte[] input = data.toByteArray();
        if (input.length > R_BYTE_NUM) {
            logger.error("Input error, the byte length {} is not as expected {}",
                    input.length, R_BYTE_NUM);
            return BigInteger.ZERO;
        }
        // Standardize the data to 128 bit
        byte[] inputFormatted = new byte[R_BYTE_NUM];
        System.arraycopy(input, 0, inputFormatted, R_BYTE_NUM - input.length, input.length);
        // Expanded to 1024 bits in equal proportion
        byte[] output = new byte[RSA_BYTE_NUM];
        int factor = output.length / inputFormatted.length;
        for (int i = 0; i < inputFormatted.length; i++) {
            output[i * factor] = inputFormatted[i];
        }
        return new BigInteger(output);
    }

    public static void main(String[] args) {
        byte[] input = new byte[16];
        new SecureRandom().nextBytes(input);
        BigInteger bigInteger = dataPadding(new BigInteger(input));
        System.out.println(bigInteger);
    }
}
