package org.bitkernel.enigma;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public class EnigmaMessage {
    @Getter
    private final int[] positions;
    @Getter
    private final String str;
}
