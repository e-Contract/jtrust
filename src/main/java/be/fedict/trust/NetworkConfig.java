/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.fedict.trust;

/**
 * Network configuration.
 * 
 * @author fcorneli
 * 
 */
public class NetworkConfig {

	private final String proxyHost;

	private final int proxyPort;

	public NetworkConfig(String proxyHost, int proxyPort) {
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
	}

	public String getProxyHost() {
		return this.proxyHost;
	}

	public int getProxyPort() {
		return this.proxyPort;
	}
}
