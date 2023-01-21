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

import be.fedict.trust.linker.TrustLinkerResultException;

public interface CriticalExtensionValidator {

	void process(X509Certificate certificate) throws TrustLinkerResultException;
}
