/*
 * Java Trust Project.
 * Copyright (C) 2009-2010 FedICT.
 * Copyright (C) 2014-2019 e-Contract.be BVBA.
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

package be.fedict.trust.constraints;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TSPUtil;
import org.bouncycastle.tsp.TSPValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * TSA Certificate Constraint implementation. This CertificateConstraint
 * implementation will check if the ExtendedKeyUsage extension with value
 * id-kp-timeStamping
 * 
 * @author Wim Vandenhaute
 */
public class TSACertificateConstraint implements CertificateConstraint {

	private static final Logger LOGGER = LoggerFactory.getLogger(TSACertificateConstraint.class);

	/**
	 * Main constructor.
	 */
	public TSACertificateConstraint() {
	}

	@Override
	public void check(X509Certificate certificate) throws TrustLinkerResultException {

		// check ExtendedKeyUsage extension: id-kp-timeStamping
		X509CertificateHolder x509CertificateHolder;
		try {
			x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("certificate encoding error: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		try {
			TSPUtil.validateCertificate(x509CertificateHolder);
		} catch (TSPValidationException e) {
			LOGGER.error("ExtendedKeyUsage extension with value \"id-kp-timeStamping\" not present.");
			throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"id-kp-timeStamping ExtendedKeyUsage not present");
		}
	}
}
