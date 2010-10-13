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

package test.unit.be.fedict.trust;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import be.fedict.trust.NetworkConfig;

public class NetworkConfigTest {

	@Test
	public void testNetworkConfig() throws Exception {

		// setup
		String proxyHost = "host";
		int proxyPort = 8008;

		// operate
		NetworkConfig networkConfig = new NetworkConfig(proxyHost, proxyPort);

		// verify
		assertEquals(proxyHost, networkConfig.getProxyHost());
		assertEquals(proxyPort, networkConfig.getProxyPort());
	}

}
