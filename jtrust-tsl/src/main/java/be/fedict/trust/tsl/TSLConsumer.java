/*
 * Java Trust Project.
 * Copyright (C) 2009-2011 FedICT.
 * Copyright (C) 2019-2020 e-Contract.be BVBA.
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

package be.fedict.trust.tsl;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

/**
 * Interface for a Trusted List consumer component.
 * 
 * @author Frank Cornelis
 * 
 */
public interface TSLConsumer {

	/**
	 * Called by the TSLParser when parsing a Trusted List. Communicated the Trusted
	 * List sequence number to this TSL consumer component.
	 * 
	 * @param tslSequenceNumber
	 */
	void setTSLSequenceNumber(BigInteger tslSequenceNumber);

	void service(String serviceTypeIdentifier, X509Certificate serviceCertificate) throws Exception;

	void error(String tslLocation, Exception e);
}
