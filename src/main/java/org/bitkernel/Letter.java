package org.bitkernel;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.PublicKey;

@AllArgsConstructor
public class Letter {
    @Getter
    @Setter
    private String msg;
    @Getter
    private byte[] signature;
    @Getter
    private PublicKey publicKey;
}
