package org.apache.flink.runtime.blob;

import java.io.IOException;
import java.net.InetAddress;

import java.net.ServerSocket;
import java.util.Collections;
import java.util.Iterator;

import javax.net.ServerSocketFactory;

import org.apache.flink.configuration.BlobServerOptions;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.JobManagerOptions;
import org.apache.flink.configuration.SecurityOptions;
import org.apache.flink.runtime.net.SSLUtils;
import org.apache.flink.util.NetUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BlobServerSocket {

    private static final Logger LOG = LoggerFactory.getLogger(BlobServerSocket.class);

    private final Configuration config;
    private final int backlog;
    private final String serverPortRange;
    private ServerSocket serverSocket;
    private final int maxConnections;
    private boolean firstCreation;


    public BlobServerSocket(Configuration config, int backlog, int maxConnections)
            throws IOException {
        this.config = config;
        this.backlog = backlog;
        this.maxConnections = maxConnections;

        serverPortRange = config.get(BlobServerOptions.PORT);
        this.firstCreation = true;
        createSocket();
        this.firstCreation = false;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    public void createSocket() throws IOException {
        Iterator<Integer> ports;
        if (firstCreation) {
            ports = NetUtils.getPortRangeFromString(serverPortRange);
        } else {
            ports = Collections.singleton(serverSocket.getLocalPort()).iterator();
        }
        if (serverSocket != null) {
            close(serverSocket);
        }

        final ServerSocketFactory socketFactory;
        if (SecurityOptions.isInternalSSLEnabled(config)
                && config.get(BlobServerOptions.SSL_ENABLED)) {
            try {
                socketFactory = SSLUtils.createSSLServerSocketFactory(config);
            } catch (Exception e) {
                throw new IOException("Failed to initialize SSL for the blob server", e);
            }
        } else {
            socketFactory = ServerSocketFactory.getDefault();
        }

        final int finalBacklog = backlog;
        final String bindHost =
                config.getOptional(JobManagerOptions.BIND_HOST)
                        .orElseGet(NetUtils::getWildcardIPAddress);

        this.serverSocket =
                NetUtils.createSocketFromPorts(
                        ports,
                        (port) ->
                                socketFactory.createServerSocket(
                                        port, finalBacklog, InetAddress.getByName(bindHost)));

        if (serverSocket == null) {
            throw new IOException(
                    "Unable to open BLOB Server in specified port range: " + serverPortRange);
        }

        if (LOG.isInfoEnabled()) {
            LOG.info(
                    "Started BLOB server at {}:{} - max concurrent requests: {} - max backlog: {}",
                    serverSocket.getInetAddress().getHostAddress(),
                    getPort(),
                    maxConnections,
                    backlog);
        }
    }

    /**
     * Returns the port on which the server is listening.
     *
     * @return port on which the server is listening
     */
    public int getPort() {
        return serverSocket.getLocalPort();
    }

    public void close() throws IOException {
        close(serverSocket);
    }

    private void close(ServerSocket serverSocketToClose) throws IOException {
        if (LOG.isInfoEnabled()) {
            if (serverSocketToClose != null) {
                LOG.info(
                        "Stopped BLOB server at {}:{}",
                        serverSocketToClose.getInetAddress().getHostAddress(),
                        getPort());
            } else {
                LOG.info("Stopped BLOB server before initializing the socket");
            }
        }
        if (serverSocketToClose != null) {
            serverSocketToClose.close();
        }
    }
}
