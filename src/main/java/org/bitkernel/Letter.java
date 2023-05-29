package org.bitkernel;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.PublicKey;

@AllArgsConstructor
public class Letter {
    @Getter
    private String msg;
    @Getter
    private byte[] signature;
    @Getter
    private PublicKey publicKey;
}
