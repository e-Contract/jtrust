/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Fallback trust linker. Implements a trust linker fallback strategy.
 * 
 * @author Frank Cornelis
 * 
 */
public class FallbackTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(FallbackTrustLinker.class);

	private List<TrustLinker> trustLinkers;

	/**
	 * Default constructor.
	 */
	public FallbackTrustLinker() {
		this.trustLinkers = new LinkedList<TrustLinker>();
	}

	/**
	 * Adds a trust linker. The order in which the trust linkers are added will
	 * determine the runtime fallback strategy.
	 * 
	 * @param trustLinker
	 *            a trust linker instance.
	 */
	public void addTrustLinker(TrustLinker trustLinker) {
		this.trustLinkers.add(trustLinker);
	}

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData) {
		for (TrustLinker trustLinker : this.trustLinkers) {
			LOG.debug("trying trust linker: "
					+ trustLinker.getClass().getSimpleName());
			TrustLinkerResult result = trustLinker.hasTrustLink(
					childCertificate, certificate, validationDate,
					revocationData);
			if (null == result) {
				continue;
			}
			return result;
		}
		return null;
	}
}
