/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.pekko.remote.transport.netty;

import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.apache.flink.shaded.netty4.io.netty.handler.ssl.util.FingerprintTrustManagerFactory;

import com.typesafe.config.Config;
import org.apache.pekko.actor.ActorSystem;
import java.util.List;

import org.apache.pekko.stream.TLSRole;

import scala.collection.JavaConverters;


/**
 * Extension of the {@link ConfigSSLEngineProvider} to use a
 * {@link FingerprintTrustManagerFactory}.
 */
@SuppressWarnings("deprecation")
public class CustomSSLEngineProvider implements SSLEngineProvider {

    private final String sslTrustStore;
    private final String sslTrustStorePassword;
    private final List<String> sslCertFingerprints;
    private final String sslKeyStoreType;
    private final String sslTrustStoreType;
    private final SSLSettings ssLSettings;
    //private final MarkerLoggingAdapter log;
    private final SSLContextLoader sslContextLoader;

    public CustomSSLEngineProvider(ActorSystem system) {
        final Config securityConfig =
                system.settings().config().getConfig("pekko.remote.classic.netty.ssl.security");
        sslTrustStore = securityConfig.getString("trust-store");
        sslTrustStorePassword = securityConfig.getString("trust-store-password");
        sslCertFingerprints = securityConfig.getStringList("cert-fingerprints");
        sslKeyStoreType = securityConfig.getString("key-store-type");
        sslTrustStoreType = securityConfig.getString("trust-store-type");
        //log = Logging.withMarker(system,  logSource.apply("test"));
        ssLSettings = new SSLSettings(securityConfig);
        sslContextLoader =new SSLContextLoader(ssLSettings, sslTrustStore, sslTrustStorePassword, sslKeyStoreType, sslTrustStoreType , sslCertFingerprints);
        System.out.println("NICO");
        FileSystemWatchService fileSystemWatchService =
                new FileSystemWatchService(Path.of(sslTrustStore).getParent().toString()) {
                    @Override
                    protected void onFileOrDirectoryModified(Path relativePath) {
                        try {
                            // TODO remove
                            System.out.println(
                                    "Reloading Internal SSL context because of certificate change");
                            sslContextLoader.loadSSLContext();
                            System.out.println("Internal SSL context reloaded successfully");
                        } catch (Exception e) {
                            System.out.println("Internal SSL context reload received exception: " + e);
                        }
                    }
                };
        fileSystemWatchService.start();
    }

    @Override
    public SSLEngine createServerSSLEngine() {
        return createSSLEngine(TLSRole.server());
    }

    @Override
    public SSLEngine createClientSSLEngine() {
        return createSSLEngine(TLSRole.client());
    }

    private SSLEngine createSSLEngine(TLSRole role) {
        return createSSLEngine(sslContextLoader.getSslContext(), role);
    }

    private SSLEngine createSSLEngine(SSLContext sslContext, TLSRole role) {
        System.out.println("NICO Creating SSL engine for " + role);
        SSLEngine engine = sslContext.createSSLEngine();

        engine.setUseClientMode(role == TLSRole.client());
        engine.setEnabledCipherSuites(JavaConverters
                .setAsJavaSet(ssLSettings.SSLEnabledAlgorithms())
                .toArray(String[]::new));
        engine.setEnabledProtocols(new String[]{ssLSettings.SSLProtocol()});

        if ((role != TLSRole.client()) && ssLSettings.SSLRequireMutualAuthentication()) {
            engine.setNeedClientAuth(true);
        }

        return engine;
    }
}
