/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.pekko.remote.transport.netty;

import org.apache.flink.shaded.netty4.io.netty.handler.ssl.util.FingerprintTrustManagerFactory;

import org.apache.pekko.remote.RemoteTransportException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.List;


public class SSLContextLoader {

    private final SSLSettings ssLSettings;
    private final String sslTrustStore;
    private final String sslTrustStorePassword;
    private final List<String> sslCertFingerprints;
    private final String sslKeyStoreType;
    private final String sslTrustStoreType;
    private SSLContext sslContext;

    public SSLContextLoader(
            SSLSettings ssLSettings,
            String sslTrustStore,
            String sslTrustStorePassword,
            String sslKeyStoreType,
            String sslTrustStoreType,
            List<String> sslCertFingerprints) {
        this.ssLSettings = ssLSettings;
        this.sslCertFingerprints = sslCertFingerprints;
        this.sslKeyStoreType = sslKeyStoreType;
        this.sslTrustStoreType = sslTrustStoreType;
        this.sslTrustStorePassword = sslTrustStorePassword;
        this.sslTrustStore = sslTrustStore;
        loadSSLContext();
    }

    void loadSSLContext() {
        try {
            System.out.println("NICO Loading SSL context");
            SecureRandom rng = createSecureRandom();
            SSLContext ctx = SSLContext.getInstance(ssLSettings.SSLProtocol());
            ctx.init(keyManagers(), trustManagers(), rng);
            this.sslContext = ctx;
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public SecureRandom createSecureRandom() {
        SecureRandom rng = new SecureRandom();
        rng.nextInt();
        return rng;
    }

    /**
     * Subclass may override to customize `KeyManager`
     */
    private KeyManager[] keyManagers()
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(
                loadKeystore(ssLSettings.SSLKeyStore(), ssLSettings.SSLKeyStorePassword()),
                ssLSettings.SSLKeyPassword().toCharArray());
        return factory.getKeyManagers();
    }


    public TrustManager[] trustManagers() {
        try {
            final TrustManagerFactory trustManagerFactory =
                    sslCertFingerprints.isEmpty()
                            ? TrustManagerFactory.getInstance(
                            TrustManagerFactory.getDefaultAlgorithm())
                            : FingerprintTrustManagerFactory.builder("SHA1")
                                    .fingerprints(sslCertFingerprints)
                                    .build();

            trustManagerFactory.init(
                    loadKeystore(sslTrustStore, sslTrustStorePassword, sslTrustStoreType));
            return trustManagerFactory.getTrustManagers();
        } catch (GeneralSecurityException | IOException e) {
            // replicate exception handling from SSLEngineProvider
            throw new RemoteTransportException(
                    "Server SSL connection could not be established because SSL context could not be constructed",
                    e);
        }
    }

    public KeyStore loadKeystore(String filename, String password) {
        try {
            return loadKeystore(filename, password, sslKeyStoreType);
        } catch (IOException | GeneralSecurityException e) {
            throw new RemoteTransportException(
                    "Server SSL connection could not be established because key store could not be loaded",
                    e);
        }
    }

    private KeyStore loadKeystore(String filename, String password, String keystoreType)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try (InputStream fin = Files.newInputStream(Paths.get(filename))) {
            char[] passwordCharArray = password.toCharArray();
            keyStore.load(fin, passwordCharArray);
        }
        return keyStore;
    }
}
