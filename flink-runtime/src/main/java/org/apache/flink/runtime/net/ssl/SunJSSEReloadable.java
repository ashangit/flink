/*
 * Copyright (c) 1999, 2024, Oracle and/or its affiliates. All rights reserved.
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

import static sun.security.util.SecurityConstants.PROVIDER_VER;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.HashMap;
import java.util.List;

/**
 * The JSSE provider.
 */
public class SunJSSEReloadable extends Provider {

    @java.io.Serial
    private static final long serialVersionUID = 3231825739635378733L;

    private static final String info = "Sun JSSE provider" +
        "(PKCS12, SunX509/PKIX key/trust factories, " +
        "SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)";

    public SunJSSEReloadable() {
        super("SunJSSEReloadable", PROVIDER_VER, info);
        registerAlgorithms();
    }

    @SuppressWarnings("removal")
    private void registerAlgorithms() {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            doRegister();
            return null;
        });
    }

    private void ps(String type, String algo, String cn,
            List<String> a, HashMap<String, String> attrs) {
        putService(new Service(this, type, algo, cn, a, attrs));
    }

    private void doRegister() {
        System.out.println("NICO My reloadable implementation");
        ps("KeyManagerFactory", "SunX509",
            "org.apache.flink.runtime.net.ssl.KeyManagerFactoryImplReloadable$SunX509", null, null);
    }
}
