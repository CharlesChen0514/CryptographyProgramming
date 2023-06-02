package org.bitkernel;

import com.sun.istack.internal.NotNull;
import lombok.Getter;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Config {
    @Getter
    private static String alphabets;
    @Getter
    private static int[] positions;
    @Getter
    private static int clientPort;
    @Getter
    private static int mpcMainPort;
    @Getter
    private static String mpcMainIp;
    @Getter
    private static int mpcPort;

    @NotNull
    public static Properties readProperty(@NotNull String fileName) {
        Properties prop = new Properties();
        try {
            FileInputStream input = new FileInputStream("src/main/resources/" + fileName);
            prop.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return prop;
    }

    public static void init() {
        Properties properties = readProperty("config.properties");
        alphabets = properties.getProperty("alphabets");
        int idx1 = Integer.parseInt(properties.getProperty("quickRotorPos"));
        int idx2 = Integer.parseInt(properties.getProperty("midRotorPos"));
        int idx3 = Integer.parseInt(properties.getProperty("slowRotorPos"));
        positions = new int[]{idx1, idx2, idx3};

        clientPort = Integer.parseInt(properties.getProperty("clientPort"));
        mpcMainPort = Integer.parseInt(properties.getProperty("mpcMainPort"));
        mpcMainIp = properties.getProperty("mpcMainIp");
        mpcPort = Integer.parseInt(properties.getProperty("mpcPort"));
    }
}
