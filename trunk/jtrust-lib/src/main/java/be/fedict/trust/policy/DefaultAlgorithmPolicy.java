/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.trust.policy;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * A default implementation of an algorithm policy.
 * <p/>
 * Per default we kick out MD5 RSA signatures.
 * 
 * @author Frank Cornelis
 * 
 */
public class DefaultAlgorithmPolicy implements AlgorithmPolicy {

	private static final Log LOG = LogFactory
			.getLog(DefaultAlgorithmPolicy.class);

	@Override
	public void checkSignatureAlgorithm(String signatureAlgorithm)
			throws TrustLinkerResultException {
		LOG.debug("validate signature algorithm: " + signatureAlgorithm);
		if (signatureAlgorithm.contains("MD5")
				|| signatureAlgorithm.equals("1.2.840.113549.1.1.4")) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.INVALID_ALGORITHM,
					"MD5 not allowed");
		}
	}
}
