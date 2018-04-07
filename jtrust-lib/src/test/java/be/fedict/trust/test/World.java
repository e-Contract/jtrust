/*
 * Java Trust Project.
 * Copyright (C) 2018 e-Contract.be BVBA.
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

package be.fedict.trust.test;

import java.util.LinkedList;
import java.util.List;

import org.mortbay.jetty.testing.ServletTester;

public class World {

	private final List<EndpointProvider> endpointProviders;

	private boolean running;

	private ServletTester servletTester;

	public World() {
		this.endpointProviders = new LinkedList<>();
	}

	public void addEndpointProvider(EndpointProvider endpointProvider) {
		if (this.running) {
			throw new IllegalStateException();
		}
		this.endpointProviders.add(endpointProvider);
	}

	public void start() throws Exception {
		this.servletTester = new ServletTester();

		for (EndpointProvider endpointProvider : this.endpointProviders) {
			endpointProvider.addEndpoints(this.servletTester);
		}

		this.servletTester.start();
		String url = this.servletTester.createSocketConnector(true);
		this.running = true;

		for (EndpointProvider endpointProvider : this.endpointProviders) {
			endpointProvider.started(url);
		}
	}

	public void stop() throws Exception {
		this.servletTester.stop();
		this.running = false;
	}

	public boolean isRunning() {
		return this.running;
	}
}
