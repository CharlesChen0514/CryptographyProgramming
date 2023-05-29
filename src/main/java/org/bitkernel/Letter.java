package org.bitkernel;

import lombok.AllArgsConstructor;

import java.security.PublicKey;

@AllArgsConstructor
public class Letter {
    private String msg;
    private byte[] signature;
    private PublicKey publicKey;
}
