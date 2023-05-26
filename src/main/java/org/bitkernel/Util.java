package org.bitkernel;

import com.sun.istack.internal.NotNull;

public class Util {
    public static int[] byteArrayToIntArray(@NotNull byte[] bs) {
        int[] res = new int[bs.length];
        for (int i = 0; i < res.length; i++) {
            res[i] = bs[i] & 0xFF;
        }
        return res;
    }

    public static byte[] intArrayToByteArray(@NotNull int[] intArray) {
        byte[] res = new byte[intArray.length];
        for (int i = 0; i < intArray.length; i++) {
            res[i] = (byte) intArray[i];
        }
        return res;
    }
}
