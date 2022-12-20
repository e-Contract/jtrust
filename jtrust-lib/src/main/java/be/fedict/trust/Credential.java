/*
 * Java Trust Project.
 * Copyright (C) 2010 FedICT.
 * Copyright (C) 2022 e-Contract.be BV.
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
 * Stores a credential required to access a protected PKI online service.
 * 
 * @author Frank Cornelis
 * 
 */
public class Credential {

	private final String host;

	private final int port;

	private final String realm;

	private final String scheme;

	private final String username;

	private final String password;

	/**
	 * Main constructor.
	 * 
	 * @param host     the service host which requires the credential.
	 * @param port     the service port which requires the credential.
	 * @param realm    the service realm which requires the credential.
	 * @param scheme   the service scheme which requires the credential.
	 * @param username the username.
	 * @param password the password.
	 */
	public Credential(String host, int port, String realm, String scheme, String username, String password) {
		this.host = host;
		this.port = port;
		this.realm = realm;
		this.scheme = scheme;
		this.username = username;
		this.password = password;
	}

	/**
	 * Any scheme is allowed.
	 * 
	 * @param host
	 * @param port
	 * @param realm
	 * @param username
	 * @param password
	 */
	public Credential(String host, int port, String realm, String username, String password) {
		this(host, port, realm, null, username, password);
	}

	/**
	 * Any scheme and any realm is allowed.
	 * 
	 * @param host
	 * @param port
	 * @param username
	 * @param password
	 */
	public Credential(String host, int port, String username, String password) {
		this(host, port, null, username, password);
	}

	/**
	 * Any scheme, realm and port is allowed.
	 * 
	 * @param host
	 * @param username
	 * @param password
	 */
	public Credential(String host, String username, String password) {
		this(host, -1, username, password);
	}

	/**
	 * Any scheme, realm, port and host is allowed.
	 * 
	 * @param username
	 * @param password
	 */
	public Credential(String username, String password) {
		this(null, username, password);
	}

	public String getHost() {
		return this.host;
	}

	public int getPort() {
		return this.port;
	}

	public String getRealm() {
		return this.realm;
	}

	public String getScheme() {
		return this.scheme;
	}

	public String getUsername() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}
}
