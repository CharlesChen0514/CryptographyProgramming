package org.bitkernel.enigma;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.Setter;

public class Enigma {
    private final Rotor quickRotor;
    private final Rotor midRotor;
    private final Rotor slowRotor;
    private final Reflector reflector;

    public Enigma(@NotNull String alphabets, @NotNull int[] positions) {
        quickRotor = new Rotor(alphabets);
        midRotor = new Rotor(alphabets);
        slowRotor = new Rotor(alphabets);
        setPos(positions[0], positions[1], positions[2]);
        reflector = new Reflector();
    }

    public void rotate() {
        quickRotor.rotate();
        if (quickRotor.getPos() == 0) {
            midRotor.rotate();
            if (midRotor.getPos() == 0) {
                slowRotor.rotate();
            }
        }
    }

    public void setPos(int idx1, int idx2, int idx3) {
        quickRotor.setPos(idx1);
        midRotor.setPos(idx2);
        slowRotor.setPos(idx3);
    }

    @NotNull
    public String encode(@NotNull String input) {
        StringBuilder sb = new StringBuilder();
        input = input.toLowerCase();
        for (char c : input.toCharArray()) {
            char encrypted = quickRotor.getChar(c);
            encrypted = midRotor.getChar(encrypted);
            encrypted = slowRotor.getChar(encrypted);

            encrypted = reflector.reflect(encrypted);

            encrypted = slowRotor.getInvChar(encrypted);
            encrypted = midRotor.getInvChar(encrypted);
            encrypted = quickRotor.getInvChar(encrypted);
            sb.append(encrypted);

            rotate();
        }
        return sb.toString();
    }

    @NotNull
    public String decode(@NotNull String message) {
        return encode(message);
    }

    public static void main(String[] args) {
        String alphabets = "abcdefghijklmnopqrstuvwxyz";
        int[] ps = {0, 1, 2};
        Enigma encryptedEnigma = new Enigma(alphabets, ps);
        String key = "chenjial";

        String d1Str = encryptedEnigma.encode(key);
        String d2Str = encryptedEnigma.encode(key);
        System.out.println(d1Str);
        System.out.println(d2Str);

        Enigma decryptedEnigma = new Enigma(alphabets, ps);
        String key1 = decryptedEnigma.decode(d1Str);
        String key2 = decryptedEnigma.decode(d2Str);
        System.out.println(key1);
        System.out.println(key2);
    }
}

class Rotor {
    private final static int CHAR_NUMBER = 26;
    private final String alphabets;
    @Getter
    @Setter
    private int pos = 0;

    public Rotor(@NotNull String alphabets) {
        this.alphabets = alphabets;
    }

    public void rotate() {
        pos = (pos + 1) % CHAR_NUMBER;
    }

    public char getChar(char c) {
        int index = (alphabets.indexOf(c) + pos) % CHAR_NUMBER;
        return alphabets.charAt(index);
    }

    public char getInvChar(char c) {
        int index = (alphabets.indexOf(c) - pos + CHAR_NUMBER) % CHAR_NUMBER;
        return alphabets.charAt(index);
    }
}

class Reflector {
    private final String alphabets = "abcdefghijklmnopqrstuvwxyz";
    private final String reflected = "yruhqsldpxngokmiebfzcwvjat";

    public char reflect(char c) {
        return reflected.charAt(alphabets.indexOf(c));
    }
}