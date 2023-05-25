package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.bitkernel.rsa.RSAKeyPair;

import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
public class MPCMain {

    @NotNull
    public List<Integer> generatePath(int size) {
        List<Integer> path = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            path.add(i);
        }
        Collections.shuffle(path);
        return path;
    }

    @NotNull
    public BigInteger getSumD(@NotNull BigInteger x, @NotNull BigInteger... rValues) {
        BigInteger sumD = new BigInteger(x.toByteArray());
        for (BigInteger r : rValues) {
            sumD = sumD.subtract(r);
        }
        return sumD;
    }

    @NotNull
    public String generateGroupTag(@NotNull User[] users) {
        StringBuilder sb = new StringBuilder();
        for (User user: users) {
            sb.append(user.getName()).append("@");
        }
        return sb.toString();
    }

    @NotNull
    public RSAKeyPair generateRSAKeyPair(@NotNull BigInteger d1Sum,
                                         @NotNull BigInteger d2Sum) {
        BigInteger d1SumPadding = dataPadding(d1Sum);
        BigInteger d2SumPadding = dataPadding(d2Sum);
        BigInteger p = findNextPrime(d1SumPadding);
        BigInteger q = findNextPrime(d2SumPadding);
        return new RSAKeyPair(p, q);
    }

    @NotNull
    private BigInteger findNextPrime(@NotNull BigInteger base) {
        while (!base.isProbablePrime(1024)) {
            base = base.add(BigInteger.ONE);
        }
        return base;
    }

    private byte[] removeLeadingZero(byte[] bytes) {
        if (bytes[0] != 0) {
            return bytes;
        } else {
            byte[] result = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, result, 0, result.length);
            return result;
        }
    }

    @NotNull
    public static BigInteger dataPadding(@NotNull BigInteger data) {
        byte[] input = data.toByteArray();
        if (input.length > Constant.R_BYTE_NUM) {
            logger.error("Input error, the byte length {} is not as expected {}",
                    input.length, Constant.R_BYTE_NUM);
            return BigInteger.ZERO;
        }
        byte[] inputFormatted = new byte[Constant.R_BYTE_NUM];
        System.arraycopy(input, 0, inputFormatted, Constant.R_BYTE_NUM - input.length, input.length);
        byte[] output = new byte[Constant.RSA_BYTE_NUM];
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
