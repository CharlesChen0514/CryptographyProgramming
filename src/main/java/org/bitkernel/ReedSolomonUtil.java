package org.bitkernel;

import com.google.zxing.common.reedsolomon.GenericGF;
import com.google.zxing.common.reedsolomon.ReedSolomonDecoder;
import com.google.zxing.common.reedsolomon.ReedSolomonEncoder;
import com.google.zxing.common.reedsolomon.ReedSolomonException;
import com.sun.istack.internal.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ReedSolomonUtil {
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

    @NotNull
    public static byte[] encode(@NotNull byte[] toEncode, int ecBytes) {
        int[] intArray = byteArrayToIntArray(toEncode);
        ReedSolomonEncoder encoder = new ReedSolomonEncoder(GenericGF.AZTEC_DATA_8);
        encoder.encode(intArray, ecBytes);
        return intArrayToByteArray(intArray);
    }

    @NotNull
    public static byte[] decode(@NotNull byte[] toDecode, int ecBytes) {
        int[] intArray = byteArrayToIntArray(toDecode);
        ReedSolomonDecoder decoder = new ReedSolomonDecoder(GenericGF.AZTEC_DATA_8);
        try {
            decoder.decode(intArray, ecBytes);
        } catch (ReedSolomonException e) {
            throw new RuntimeException(e);
        }
        return intArrayToByteArray(intArray);
    }
}
