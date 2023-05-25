package org.bitkernel;

import com.google.zxing.common.reedsolomon.GenericGF;
import com.google.zxing.common.reedsolomon.ReedSolomonDecoder;
import com.google.zxing.common.reedsolomon.ReedSolomonEncoder;
import com.sun.istack.internal.NotNull;
import lombok.Getter;
import org.bitkernel.rsa.RSAKeyPair;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

public class StorageGateway {
    private final static int REDUNDANCIES_SIZE = 2;
    private final static int DATA_BLOCK_NUM_PER_KEY = 4;
    private final GenericGF gf = GenericGF.AZTEC_DATA_8;
    private final ReedSolomonEncoder encoder = new ReedSolomonEncoder(gf);
    private final ReedSolomonDecoder decoder = new ReedSolomonDecoder(gf);
    /** Group tag -> public key*/
    private final Map<String, PublicKey> publicKeyMap = new LinkedHashMap<>();
    /** Group tag -> private key */
    private final Map<String, PrivateKey> privateKeyMap = new LinkedHashMap<>();
    /** User name -> Group tag -> sub private key */
    private final Map<String, Map<String, BigInteger>> userSubPriKeyMap = new LinkedHashMap<>();
    private final Storage[] storages = new Storage[3];

    public StorageGateway() {
        for (int i = 0; i < storages.length; i++) {
            storages[i] = new Storage();
        }
    }

    public void store(@NotNull User[] group,
                      @NotNull String groupTag,
                      @NotNull RSAKeyPair rsAKeyPair) {
        publicKeyMap.put(groupTag, rsAKeyPair.getPublicKey());
        privateKeyMap.put(groupTag, rsAKeyPair.getPrivateKey());

        Map<User, byte[]> userSubPriKeyMap = getPriKeySlicingScheme(group, groupTag, rsAKeyPair.getPrivateKey());
//        for (Map.Entry<User, byte[]> entry: userSubPriKeyMap.entrySet()) {
//
//        }
    }

//    @NotNull
//    private DataBlock[] generateDataBlocks(@NotNull byte[] byteData) {
//        int[] intArr = byteArrayToIntArray(byteData);
//        int blockSize = (int) Math.ceil(intArr.length * 1.0 / DATA_BLOCK_NUM_PER_KEY);
//
//    }

    @NotNull
    public static int[] byteArrayToIntArray(@NotNull byte[] byteArray) {
        int[] intArray = new int[byteArray.length];
        for (int i = 0; i < byteArray.length; i++) {
            intArray[i] = byteArray[i] & 0xFF;
        }
        return intArray;
    }

    @NotNull
    private Map<User, byte[]> getPriKeySlicingScheme(@NotNull User[] group,
                                                     @NotNull String groupTag,
                                                     @NotNull PrivateKey priKey) {
//        int userNum = group.length;
//        int subPriKeyLen = (int) Math.ceil(privateKey.length * 1.0 / userNum);
        Map<User, byte[]> subPriKeyMap = new LinkedHashMap<>();
//        for (int i = 0; i < userNum; i++) {
//            User user = group[i];
//            byte[] subPriKey = new byte[subPriKeyLen];
//            int srcPos = i * subPriKeyLen;
//            int remainLen = privateKey.length - srcPos;
//            int copyLen = Math.min(remainLen, subPriKeyLen);
//            System.arraycopy(privateKey, srcPos, subPriKey, 0, copyLen);
//            userSubPriKeyMap.putIfAbsent(user.getName(), new LinkedHashMap<>());
//            userSubPriKeyMap.get(user.getName()).put(groupTag, new BigInteger(subPriKey));
//            subPriKeyMap.put(user, subPriKey);
//        }
        return subPriKeyMap;
    }
}

class DataBlock {
    @Getter
    private final int k;
//    @Getter
//    private final int[] data;

    public DataBlock(int k, @NotNull byte[] byteData) {
        this.k = k;
//        data = byteArrayToIntArray(byteData);
    }
}


class Storage {
    /** User name -> group tag -> data block */
    private final Map<String, Map<String, DataBlock>> priKeyDataBlockMap = new LinkedHashMap<>();
    /** Group tag -> data block */
    private final Map<String, DataBlock> pubKeyDataBlockMap = new LinkedHashMap<>();
}
