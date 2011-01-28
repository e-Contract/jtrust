/*
 * Java Trust Project.
 * Copyright (C) 2010 FedICT.
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

import java.util.LinkedList;
import java.util.List;

import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;

/**
 * Stores credentials required to access protected online PKI services.
 * 
 * @author Frank Cornelis
 * 
 */
public class Credentials {

	private final List<Credential> credentials;

	/**
	 * Default constructor.
	 */
	public Credentials() {
		this.credentials = new LinkedList<Credential>();
	}

	/**
	 * Adds a credential to this credential store.
	 * 
	 * @param credential
	 */
	public void addCredential(Credential credential) {
		this.credentials.add(credential);
	}

	/**
	 * Gives back the list of credentials.
	 * 
	 * @return the list of credentials.
	 */
	public List<Credential> getCredentials() {
		return this.credentials;
	}

	/**
	 * Initializes the Commons HTTPClient state using the credentials stores in
	 * this credential store.
	 * 
	 * @param httpState
	 */
	public void init(HttpState httpState) {
		for (Credential credential : this.credentials) {
			AuthScope authScope = new AuthScope(credential.getHost(),
					credential.getPort(), credential.getRealm(),
					credential.getScheme());
			UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(
					credential.getUsername(), credential.getPassword());
			httpState.setCredentials(authScope, usernamePasswordCredentials);
		}
	}
}
