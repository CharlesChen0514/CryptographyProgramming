package org.bitkernel.enigma;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public class Message {
    @Getter
    private final int[] positions;
    @Getter
    private final String str;
}
