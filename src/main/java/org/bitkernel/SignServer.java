package org.bitkernel;

import com.sun.istack.internal.NotNull;
import org.bitkernel.rsa.RSAKeyPair;
import org.bitkernel.rsa.RSAUtil;

import java.security.PublicKey;

public class SignServer {
    private final RSAKeyPair rsaKeyPair = new RSAKeyPair();

    @NotNull
    public PublicKey getRSAPubKey() {
        return rsaKeyPair.getPublicKey();
    }

    @NotNull
    public void sign(@NotNull byte[] encryptReq) {
        byte[] decrypt = RSAUtil.decrypt(encryptReq, rsaKeyPair.getPrivateKey());
        String signReqString = new String(decrypt);
        String[] split = signReqString.split("-");
    }
}
