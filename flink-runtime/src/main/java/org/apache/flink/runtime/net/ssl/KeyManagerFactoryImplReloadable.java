/*
 * Copyright (c) 1999, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.apache.flink.runtime.net.ssl;

import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.flink.runtime.net.FileSystemWatchService;

abstract class KeyManagerFactoryImplReloadable extends KeyManagerFactorySpi {

    X509ExtendedKeyManager keyManager;
    boolean isInitialized;

    KeyManagerFactoryImplReloadable() {
        // empty
    }

    /**
     * Returns one key manager for each type of key material.
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (!isInitialized) {
            throw new IllegalStateException(
                        "KeyManagerFactoryImpl is not initialized");
        }
        return new KeyManager[] { keyManager };
    }

    // Factory for the SunX509 keymanager
    public static final class SunX509 extends KeyManagerFactoryImplReloadable {

        @Override
        protected void engineInit(KeyStore ks, char[] password) throws
                KeyStoreException, NoSuchAlgorithmException,
                UnrecoverableKeyException {
            try {
                keyManager = new SunX509KeyManagerImplReloadable(ks, password);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }

            FileSystemWatchService fileSystemWatchService =
                    new FileSystemWatchService(Path
                            .of("/Users/nicolas.fraison/Downloads/NettySSL/untitled/ssl_certs")
                            .toString()) {
                        @Override
                        protected void onFileOrDirectoryModified(Path relativePath) {
                            try {
                                // TODO remove
                                System.out.println(
                                        "Reloading X509Credentials SSL context because of certificate change");
                                ((SunX509KeyManagerImplReloadable) keyManager).load();
                                System.out.println(
                                        "X509Credentials SSL context reloaded successfully");
                            } catch (Exception e) {
                                System.out.println(
                                        "X509Credentials SSL context reload received exception: "
                                                + e);
                            }
                        }
                    };
            fileSystemWatchService.start();
            isInitialized = true;
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec) throws
                InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException(
                "SunX509KeyManager does not use ManagerFactoryParameters");
        }

    }

}
