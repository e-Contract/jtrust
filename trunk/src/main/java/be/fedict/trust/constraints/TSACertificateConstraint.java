/*
 * Java Trust Project.
 * Copyright (C) 2009-2010 FedICT.
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

import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.tsp.TSPUtil;
import org.bouncycastle.tsp.TSPValidationException;

import be.fedict.trust.CertificateConstraint;

/**
 * TSA Certificate Constraint implementation. This CertificateConstraint
 * implementation will check if the ExtendedKeyUsage extension with value
 * id-kp-timeStamping
 * 
 * @author Wim Vandenhaute
 */
public class TSACertificateConstraint implements CertificateConstraint {

	private static final Log LOG = LogFactory
			.getLog(TSACertificateConstraint.class);

	/**
	 * Main constructor.
	 */
	public TSACertificateConstraint() {
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean check(X509Certificate certificate) {

		// check ExtendedKeyUsage extension: id-kp-timeStamping
		try {
			TSPUtil.validateCertificate(certificate);
		} catch (TSPValidationException e) {
			LOG.error("ExtendedKeyUsage extension with value \"id-kp-timeStamping\" not present.");
			return false;
		}

		return true;
	}
}
