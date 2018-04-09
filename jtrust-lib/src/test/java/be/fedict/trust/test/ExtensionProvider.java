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

import org.bouncycastle.cert.X509v3CertificateBuilder;

/**
 * Interface for certificate extension providers.
 * 
 * @author Frank Cornelis
 *
 */
public interface ExtensionProvider {

	/**
	 * Add extensions via this method.
	 * 
	 * @param x509v3CertificateBuilder
	 * @throws Exception
	 */
	void addExtension(X509v3CertificateBuilder x509v3CertificateBuilder) throws Exception;
}
