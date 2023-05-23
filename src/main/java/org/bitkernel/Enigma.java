package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

public class Enigma {
    private final Rotor quickRotor;
    private final Rotor midRotor;
    private final Rotor slowRotor;
    private final Reflector reflector;

    public Enigma() {
        quickRotor = new Rotor();
        midRotor = new Rotor();
        slowRotor = new Rotor();
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
    public Message encode(@NotNull String input) {
        StringBuilder sb = new StringBuilder();
        input = input.toLowerCase();
        int[] positions = {quickRotor.getPos(), midRotor.getPos(), slowRotor.getPos()};
        for (char c: input.toCharArray()) {
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
        return new Message(positions, sb.toString());
    }

    @NotNull
    public String decode(@NotNull Message message) {
        int[] positions = message.getPositions();
        quickRotor.setPos(positions[0]);
        midRotor.setPos(positions[1]);
        slowRotor.setPos(positions[2]);
        return encode(message.getStr()).getStr();
    }

    public static void main(String[] args) {
        Enigma encryptedEnigma = new Enigma();
        encryptedEnigma.setPos(2, 5, 7);
        String key = "abcdef";

        Message d1Str = encryptedEnigma.encode(key);
        Message d2Str = encryptedEnigma.encode(key);
        System.out.println(d1Str.getStr());
        System.out.println(d2Str.getStr());

        Enigma decryptedEnigma = new Enigma();
        String key1 = decryptedEnigma.decode(d1Str);
        String key2 = decryptedEnigma.decode(d2Str);
        System.out.println(key1);
        System.out.println(key2);
    }
}

class Rotor {
    private final static int CHAR_NUMBER = 26;
    private final String alphabets = "abcdefghijklmnopqrstuvwxyz";
    @Getter
    @Setter
    private int pos = 0;

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

@AllArgsConstructor
class Message {
    @Getter
    private final int[] positions;
    @Getter
    private final String str;
}