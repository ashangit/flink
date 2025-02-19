/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.runtime.net;

import static org.apache.flink.runtime.net.SSLUtils.getEnabledCipherSuites;
import static org.apache.flink.runtime.net.SSLUtils.getEnabledProtocols;
import static org.apache.flink.runtime.net.SSLUtils.getKeyManagerFactory;
import static org.apache.flink.runtime.net.SSLUtils.getTrustManagerFactory;
import static org.apache.flink.shaded.netty4.io.netty.handler.ssl.SslProvider.JDK;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.configuration.SecurityOptions;

import org.apache.flink.shaded.netty4.io.netty.buffer.ByteBufAllocator;
import org.apache.flink.shaded.netty4.io.netty.handler.ssl.ApplicationProtocolNegotiator;
import org.apache.flink.shaded.netty4.io.netty.handler.ssl.ClientAuth;
import org.apache.flink.shaded.netty4.io.netty.handler.ssl.JdkSslContext;
import org.apache.flink.shaded.netty4.io.netty.handler.ssl.SslContext;
import org.apache.flink.shaded.netty4.io.netty.handler.ssl.SslContextBuilder;
import org.apache.flink.shaded.netty4.io.netty.handler.ssl.SslProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** SSL context which is able to reload keystore. */
public class ReloadableJdkSslContext extends SslContext {

    private static final Logger LOG = LoggerFactory.getLogger(ReloadableJdkSslContext.class);
    private final Configuration config;
    private final boolean clientMode;
    private final SslProvider provider;
    private volatile JdkSslContext jdkSslContext;

    public ReloadableJdkSslContext(
            Configuration config,
            boolean clientMode,
            SslProvider provider)
            throws Exception {
        this.config = config;
        this.clientMode = clientMode;
        this.provider = provider;
            loadContextInternal();
    }

    @Override
    public boolean isClient() {
        return jdkSslContext.isClient();
    }

    @Override
    public List<String> cipherSuites() {
        return jdkSslContext.cipherSuites();
    }

    @Override
    public ApplicationProtocolNegotiator applicationProtocolNegotiator() {
        return jdkSslContext.applicationProtocolNegotiator();
    }

    @Override
    public SSLEngine newEngine(ByteBufAllocator byteBufAllocator) {
        return jdkSslContext.newEngine(byteBufAllocator);
    }

    @Override
    public SSLEngine newEngine(ByteBufAllocator byteBufAllocator, String s, int i) {
        return jdkSslContext.newEngine(byteBufAllocator, s, i);
    }

    @Override
    public SSLSessionContext sessionContext() {
        return jdkSslContext.sessionContext();
    }

    public final SSLContext context() {
        return this.jdkSslContext.context();
    }

    public void reload() throws Exception {
            loadContextInternal();
    }

    private void loadContextInternal() throws Exception {
        LOG.info("Loading Internal SSL context from {}", config);

        String[] sslProtocols = getEnabledProtocols(config);
        List<String> ciphers = Arrays.asList(getEnabledCipherSuites(config));
        int sessionCacheSize = config.get(SecurityOptions.SSL_INTERNAL_SESSION_CACHE_SIZE);
        int sessionTimeoutMs = config.get(SecurityOptions.SSL_INTERNAL_SESSION_TIMEOUT);

        KeyManagerFactory kmf = getKeyManagerFactory(config, true, provider);
        ClientAuth clientAuth = ClientAuth.REQUIRE;

        final SslContextBuilder sslContextBuilder;
        if (clientMode) {
            sslContextBuilder = SslContextBuilder.forClient().keyManager(kmf);
        } else {
            sslContextBuilder = SslContextBuilder.forServer(kmf);
        }

        Optional<TrustManagerFactory> tmf = getTrustManagerFactory(config, true);
        tmf.map(sslContextBuilder::trustManager);

        jdkSslContext = (JdkSslContext) sslContextBuilder
                .sslProvider(provider)
                .protocols(sslProtocols)
                .ciphers(ciphers)
                .clientAuth(clientAuth)
                .sessionCacheSize(sessionCacheSize)
                .sessionTimeout(sessionTimeoutMs / 1000)
                .build();
    }
}
