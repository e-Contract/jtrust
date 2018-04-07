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

package be.fedict.trust.test;

import java.util.UUID;

import javax.servlet.http.HttpServlet;

import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.trust.test.CRLRevocationService.CRLServlet;

public class OCSPRevocationService implements RevocationService {

	private String identifier;

	private String ocspUri;

	public OCSPRevocationService() {
		this.identifier = UUID.randomUUID().toString();
	}

	@Override
	public void addExtension(X509v3CertificateBuilder x509v3CertificateBuilder) throws Exception {
		GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, ocspUri);
		AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
				X509ObjectIdentifiers.ocspAccessMethod, ocspName);
		x509v3CertificateBuilder.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
	}

	@Override
	public void addEndpoints(ServletTester servletTester) {
		String pathSpec = "/" + this.identifier + "/ocsp";
		ServletHolder servletHolder = servletTester.addServlet(CRLServlet.class, pathSpec);
		servletHolder.setInitParameter("identifier", this.identifier);

	}

	@Override
	public void started(String url) {
		this.ocspUri = url + "/" + this.identifier + "/ocsp";
	}

	public static final class OCSPServlet extends HttpServlet {

	}

	@Override
	public void setCertificationAuthority(CertificationAuthority certificationAuthority) {

	}
}
