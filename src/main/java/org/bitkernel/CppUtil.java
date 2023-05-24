package org.bitkernel;

import java.io.File;
import java.math.BigInteger;

public class CppUtil {

    static {
        String libPath = System.getProperty("user.dir") + File.separator + "dll" + File.separator;
        System.setProperty("java.library.path", libPath);
//        System.out.println(System.getProperty("java.library.path"));
        System.loadLibrary("libhelloTest");
    }

    public native void displayHello();
//    public native BigInteger nextPrime(String num);

    public static void main(String[] args) {
        CppUtil c = new CppUtil();
        c.displayHello();
    }
}
