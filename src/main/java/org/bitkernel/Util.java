package org.bitkernel;

import com.sun.istack.internal.NotNull;

public class Util {
    public static int[] byteArrayToIntArray(@NotNull byte[] bs) {
        int[] res = new int[bs.length / 4];
        for (int i = 0; i < res.length; i++) {
            byte[] fourBytes = new byte[4];
            System.arraycopy(bs, i * 4, fourBytes, 0, 4);
            res[i] = byteArrayToInt(fourBytes);
        }
        return res;
    }

    public static int byteArrayToInt(@NotNull byte[] b) {
        return   b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }

    public static byte[] intArrayToByteArray(@NotNull int[] intArray) {
        byte[] res = new byte[intArray.length * Integer.BYTES];
        for (int i = 0; i < intArray.length; i++) {
            byte[] bytes = intToByteArray(intArray[i]);
            System.arraycopy(bytes, 0, res, i * 4, bytes.length);
        }
        return res;
    }

    public static byte[] intToByteArray(int a) {
        return new byte[] {
                (byte) ((a >> 24) & 0xFF),
                (byte) ((a >> 16) & 0xFF),
                (byte) ((a >> 8) & 0xFF),
                (byte) (a & 0xFF)
        };
    }
}
