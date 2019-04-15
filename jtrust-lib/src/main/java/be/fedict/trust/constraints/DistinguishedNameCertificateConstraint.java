/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * Distinguished Name Certificate Constraint implemenation.
 * 
 * @author Frank Cornelis
 * 
 */
public class DistinguishedNameCertificateConstraint implements CertificateConstraint {

	private static final Logger LOGGER = LoggerFactory.getLogger(DistinguishedNameCertificateConstraint.class);

	private final X500Principal acceptedSubject;

	public DistinguishedNameCertificateConstraint(String acceptedSubjectName) {
		this.acceptedSubject = new X500Principal(acceptedSubjectName);
	}

	@Override
	public void check(X509Certificate certificate) throws TrustLinkerResultException {
		X500Principal certificateSubject = certificate.getSubjectX500Principal();
		LOGGER.debug("accepted subject: {}", this.acceptedSubject);
		if (this.acceptedSubject.equals(certificateSubject)) {
			return;
		}
		throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION, "DN mismatch");
	}
}
