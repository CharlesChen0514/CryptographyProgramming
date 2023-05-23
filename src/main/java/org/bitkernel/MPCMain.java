package org.bitkernel;

import com.sun.istack.internal.NotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
}
