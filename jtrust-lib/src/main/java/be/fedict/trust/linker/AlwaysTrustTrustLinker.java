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

package be.fedict.trust.linker;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;

/**
 * This trust linker implementation can be used to validate expired
 * certificates.
 * 
 * @author Frank Cornelis
 *
 */
public class AlwaysTrustTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(AlwaysTrustTrustLinker.class);

	@Override
	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate, X509Certificate certificate,
			Date validationDate, RevocationData revocationData, AlgorithmPolicy algorithmPolicy)
			throws TrustLinkerResultException, Exception {
		LOG.debug("trusting certificate as is: " + certificate.getSubjectX500Principal());
		return TrustLinkerResult.TRUSTED;
	}
}
