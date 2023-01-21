/*
 * Java Trust Project.
 * Copyright (C) 2022-2023 e-Contract.be BV.
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
package be.fedict.trust.ext;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.linker.TrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;

public class CriticalExtensionTrustLinker implements TrustLinker {

	private static final Logger LOGGER = LoggerFactory.getLogger(CriticalExtensionTrustLinker.class);

	private static final Map<String, CriticalExtensionValidator> criticalExtensionValidators;

	static {
		criticalExtensionValidators = new HashMap<>();
		criticalExtensionValidators.put(Extension.keyUsage.getId(), new KeyUsageCriticalExtensionValidator());
		criticalExtensionValidators.put(Extension.basicConstraints.getId(),
				new BasicConstraintsCriticalExtensionValidator());
	}

	@Override
	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate, X509Certificate certificate,
			Date validationDate, RevocationData revocationData, AlgorithmPolicy algorithmPolicy)
			throws TrustLinkerResultException, Exception {
		Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
		LOGGER.debug("critical extensions: {}", criticalExtensionOIDs);
		for (String criticalExtensionOID : criticalExtensionOIDs) {
			CriticalExtensionValidator criticalExtensionValidator = criticalExtensionValidators
					.get(criticalExtensionOID);
			if (null != criticalExtensionValidator) {
				criticalExtensionValidator.process(certificate);
			} else {
				LOGGER.warn("unknown critical extension: {}", criticalExtensionOID);
				throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST,
						"unknown critical extension: " + criticalExtensionOID);
			}
		}
		return TrustLinkerResult.UNDECIDED;
	}
}
