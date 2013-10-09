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

import java.util.Date;

import be.fedict.trust.linker.TrustLinkerResultException;

/**
 * Interface for algorithm policy validation components.
 * 
 * @author Frank Cornelis.
 * 
 */
public interface AlgorithmPolicy {

	/**
	 * Check a given signature algorithm. This check can be made time-dependent.
	 * 
	 * @param signatureAlgorithm
	 * @param validationDate
	 * @throws TrustLinkerResultException
	 * @throws Exception
	 */
	void checkSignatureAlgorithm(String signatureAlgorithm, Date validationDate)
			throws TrustLinkerResultException, Exception;
}
