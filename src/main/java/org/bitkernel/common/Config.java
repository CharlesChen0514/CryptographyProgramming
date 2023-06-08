package org.bitkernel.common;

import com.sun.istack.internal.NotNull;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

@Slf4j
public class Config {
    @Getter
    private static String alphabets;
    @Getter
    private static int[] positions;
    @Getter
    private static int mpcMainPort;
    @Getter
    private static String mpcMainIp;
    @Getter
    private static String storage1Ip;
    @Getter
    private static int storage1Port;
    @Getter
    private static String storage2Ip;
    @Getter
    private static int storage2Port;
    @Getter
    private static String storage3Ip;
    @Getter
    private static int storage3Port;
    @Getter
    private static String signServerIp;
    @Getter
    private static int signServerPort;
    @Getter
    private static String blockChainSysIp;
    @Getter
    private static int blockChainSysPort;


    static {
        Config.init();
    }

    @NotNull
    public static Properties readProperty(@NotNull String fileName) {
        Properties prop = new Properties();
        try {
            FileInputStream input;
            if (exist(fileName)) {
                input = new FileInputStream(fileName);
            } else {
                input = new FileInputStream("src/main/resources/" + fileName);
            }
            prop.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return prop;
    }

    public static boolean exist(@NotNull String filePath) {
        File file = new File(filePath);
        return file.exists();
    }

    public static void init() {
        Properties properties = readProperty("config.properties");
        alphabets = properties.getProperty("alphabets");
        int idx1 = Integer.parseInt(properties.getProperty("quickRotorPos"));
        int idx2 = Integer.parseInt(properties.getProperty("midRotorPos"));
        int idx3 = Integer.parseInt(properties.getProperty("slowRotorPos"));
        positions = new int[]{idx1, idx2, idx3};

        mpcMainIp = properties.getProperty("mpcMainIp");
        mpcMainPort = Integer.parseInt(properties.getProperty("mpcMainPort"));

        storage1Ip = properties.getProperty("storage1Ip");
        storage1Port = Integer.parseInt(properties.getProperty("storage1Port"));

        storage2Ip = properties.getProperty("storage2Ip");
        storage2Port = Integer.parseInt(properties.getProperty("storage2Port"));

        storage3Ip = properties.getProperty("storage3Ip");
        storage3Port = Integer.parseInt(properties.getProperty("storage3Port"));

        signServerIp = properties.getProperty("signServerIp");
        signServerPort = Integer.parseInt(properties.getProperty("signServerPort"));

        blockChainSysIp = properties.getProperty("blockChainSysIp");
        blockChainSysPort = Integer.parseInt(properties.getProperty("blockChainSysPort"));
    }

    @NotNull
    public static int getStoragePort(int idx) {
        switch (idx) {
            case 1:
                return storage1Port;
            case 2:
                return storage2Port;
            case 3:
                return storage3Port;
            default:
                logger.error("error idx: {}", idx);
                return -1;
        }
    }

    @NotNull
    public static String getStorageIp(int idx) {
        switch (idx) {
            case 1:
                return storage1Ip;
            case 2:
                return storage2Ip;
            case 3:
                return storage3Ip;
            default:
                logger.error("error idx: {}", idx);
                return "";
        }
    }
}
