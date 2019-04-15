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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * Key Usage Certificate Constraint implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class KeyUsageCertificateConstraint implements CertificateConstraint {

	private static final Logger LOGGER = LoggerFactory.getLogger(KeyUsageCertificateConstraint.class);

	private static final int DIGITAL_SIGNATURE_IDX = 0;
	private static final int NON_REPUDIATION_IDX = 1;
	private static final int KEY_ENCIPHERMENT_IDX = 2;
	private static final int DATA_ENCIPHERMENT_IDX = 3;
	private static final int KEY_AGREEMENT_IDX = 4;
	private static final int KEY_CERT_SIGN_IDX = 5;
	private static final int CRL_SIGN_IDX = 6;
	private static final int ENCIPHER_ONLY_IDX = 7;
	private static final int DECIPHER_ONLY_IDX = 8;

	private final Boolean[] mask;

	/**
	 * Default constructor.
	 */
	public KeyUsageCertificateConstraint() {
		this.mask = new Boolean[9];
	}

	public void setDigitalSignatureFilter(Boolean flag) {
		this.mask[DIGITAL_SIGNATURE_IDX] = flag;
	}

	public void setNonRepudiationFilter(Boolean flag) {
		this.mask[NON_REPUDIATION_IDX] = flag;
	}

	public void setKeyEnciphermentFilter(Boolean flag) {
		this.mask[KEY_ENCIPHERMENT_IDX] = flag;
	}

	public void setDataEnciphermentFilter(Boolean flag) {
		this.mask[DATA_ENCIPHERMENT_IDX] = flag;
	}

	public void setKeyAgreementFilter(Boolean flag) {
		this.mask[KEY_AGREEMENT_IDX] = flag;
	}

	public void setKeyCertificateSigningFilter(Boolean flag) {
		this.mask[KEY_CERT_SIGN_IDX] = flag;
	}

	public void setCRLSigningFilter(Boolean flag) {
		this.mask[CRL_SIGN_IDX] = flag;
	}

	public void setEncipherOnlyFilter(Boolean flag) {
		this.mask[ENCIPHER_ONLY_IDX] = flag;
	}

	public void setDecipherOnlyFilter(Boolean flag) {
		this.mask[DECIPHER_ONLY_IDX] = flag;
	}

	@Override
	public void check(X509Certificate certificate) throws TrustLinkerResultException {
		boolean[] keyUsage = certificate.getKeyUsage();
		if (null == keyUsage) {
			LOGGER.debug("no key usage extension for certificate: {}", certificate.getSubjectX500Principal());
			throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing key usage extension");
		}
		for (int idx = 0; idx < this.mask.length; idx++) {
			Boolean flag = this.mask[idx];
			if (null == flag) {
				continue;
			}
			if (false == flag) {
				if (keyUsage[idx]) {
					LOGGER.debug("should not have key usage: {}", idx);
					throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
							"should not have key usage flag: " + idx);
				}
			} else {
				if (false == keyUsage[idx]) {
					LOGGER.debug("missing key usage: {}", idx);
					throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
							"missing key usage flag: " + idx);
				}
			}
		}
		LOGGER.debug("key usage checked");
	}
}
