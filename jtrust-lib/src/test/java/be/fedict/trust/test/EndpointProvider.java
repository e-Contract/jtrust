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

import org.mortbay.jetty.testing.ServletTester;

/**
 * Interface for endpoint providers.
 * 
 * @author Frank Cornelis
 * @see World
 */
public interface EndpointProvider {

	/**
	 * Adds a servlet endpoint to the Jetty servlet tester.
	 * 
	 * @param servletTester
	 * @throws Exception
	 */
	void addEndpoints(ServletTester servletTester) throws Exception;

	/**
	 * Called when the corresponding world has been started.
	 * 
	 * @param url
	 *            the base URL of the embedded Jetty servlet container.
	 * @throws Exception
	 */
	void started(String url) throws Exception;
}
