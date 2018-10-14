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

/**
 * A world manages all entities that have endpoints (like CRL, OCSL, TSA). After
 * adding all endpoints, you have to start the world. At the end, you can stop
 * it. A world also managed the clock.
 * 
 * @author Frank Cornelis
 *
 */
public class World {

	private final List<EndpointProvider> endpointProviders;

	private boolean running;

	private ServletTester servletTester;

	private final Clock clock;

	/**
	 * Default constructor. The default world is using a local machine clock.
	 */
	public World() {
		this(new LocalClock());
	}

	/**
	 * Main constructor.
	 * 
	 * @param clock
	 *            the clock to be used by the unit test PKI world.
	 */
	public World(Clock clock) {
		this.clock = clock;
		this.endpointProviders = new LinkedList<>();
	}

	/**
	 * Adds an endpoint that has to be published by this world.
	 * 
	 * @param endpointProvider
	 */
	public void addEndpointProvider(EndpointProvider endpointProvider) {
		if (this.running) {
			throw new IllegalStateException();
		}
		this.endpointProviders.add(endpointProvider);
	}

	/**
	 * Starts the unit test PKI world. This action will start a servlet container
	 * exposing all previously registered endpoints.
	 * 
	 * @throws Exception
	 */
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

	/**
	 * Gives back the clock of this unit test PKI world.
	 * 
	 * @return
	 */
	public Clock getClock() {
		return this.clock;
	}

	/**
	 * Stops the unit test PKI world. This will shut down the underlying servlet
	 * container with all the endpoints.
	 * 
	 * @throws Exception
	 */
	public void stop() throws Exception {
		this.servletTester.stop();
		this.running = false;
	}

	/**
	 * Verifies whether this unit test PKI world is running or not.
	 * 
	 * @return
	 */
	public boolean isRunning() {
		return this.running;
	}
}
