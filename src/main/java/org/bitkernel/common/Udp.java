package org.bitkernel.common;

import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;

@Slf4j
public class Udp {
    private static final int BUFF_LEN = 4096;
    @Getter
    private int port;
    @Getter
    private DatagramSocket socket;

    public Udp(int port) {
        try {
            this.port = port;
            socket = new DatagramSocket(port);
        } catch (SocketException e) {
            logger.error("Attempt to bind udp port {} failed", port);
            System.exit(-1);
        }
    }

    public Udp() {
        try {
            socket = new DatagramSocket();
            this.port = socket.getLocalPort();
        } catch (SocketException e) {
            logger.error("Attempt to bind udp port {} failed", port);
            System.exit(-1);
        }
    }

    public void send(@NotNull String ip, int port,
                     @NotNull String dataStr) {
        byte[] bytes = dataStr.getBytes();
        send(ip, port, bytes);
    }

    public void send(@NotNull String ip, int port,
                     @NotNull byte[] bytes) {
        String dataStr = new String(bytes);
        InetSocketAddress socAddr = new InetSocketAddress(ip, port);
        DatagramPacket packet = new DatagramPacket(bytes, 0, bytes.length, socAddr);
        try {
            socket.send(packet);
            logger.debug("UDP send data [{}] to {} success", dataStr, socAddr);
        } catch (IOException e) {
            logger.debug("UDP send data [{}] to {} failed", dataStr, socAddr);
        }
    }

    public void send(@NotNull DatagramPacket pkt,
                     @NotNull String dataStr) {
        byte[] bytes = dataStr.getBytes();
        DatagramPacket packet = new DatagramPacket(bytes, 0, bytes.length, pkt.getSocketAddress());
        try {
            socket.send(packet);
            logger.debug("UDP send data [{}] to {} success", dataStr, pkt.getSocketAddress());
        } catch (IOException e) {
            logger.debug("UDP send data [{}] to {} failed", dataStr, pkt.getSocketAddress());
        }
    }

    @Nullable
    public DatagramPacket receivePkt() {
        try {
            byte[] buff = new byte[BUFF_LEN];
            DatagramPacket packet = new DatagramPacket(buff, buff.length);
            socket.receive(packet);
            return packet;
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    @NotNull
    public String receiveString() {
        DatagramPacket packet = receivePkt();
        if (packet == null) {
            return "";
        }
        return pktToString(packet);
    }

    @NotNull
    public String pktToString(@NotNull DatagramPacket pkt) {
        byte[] bytes = pkt.getData();
        String string = new String(bytes, 0, pkt.getLength());
        logger.debug("UDP receive pkt: {}", string);
        return string;
    }

    public void close() {
        socket.close();
    }
}