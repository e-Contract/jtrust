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

/**
 * Fallback trust linker. Implements a trust linker fallback strategy.
 * 
 * @author Frank Cornelis
 * 
 */
public class FallbackTrustLinker implements TrustLinker {

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
	 */
	public void addTrustLinker(TrustLinker trustLinker) {
		this.trustLinkers.add(trustLinker);
	}

	public Boolean hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate) {
		for (TrustLinker trustLinker : this.trustLinkers) {
			Boolean result = trustLinker.hasTrustLink(childCertificate,
					certificate, validationDate);
			if (null == result) {
				continue;
			}
			return result;
		}
		return null;
	}
}
