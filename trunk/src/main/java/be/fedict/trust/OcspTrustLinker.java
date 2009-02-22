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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

public class OcspTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(OcspTrustLinker.class);

	public Boolean hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate) {
		URI ocspUri = getOcspUri(childCertificate);
		if (null == ocspUri) {
			return null;
		}
		LOG.debug("OCSP URI: " + ocspUri);
		// TODO
		return null;
	}

	public URI getOcspUri(X509Certificate certificate) {
		URI ocspURI = getAccessLocation(certificate,
				X509ObjectIdentifiers.ocspAccessMethod);
		return ocspURI;
	}

	private URI getAccessLocation(X509Certificate certificate,
			DERObjectIdentifier accessMethod) {
		byte[] authInfoAccessExtensionValue = certificate
				.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}
		AuthorityInformationAccess authorityInformationAccess;
		try {
			DEROctetString oct = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(authInfoAccessExtensionValue))
					.readObject());
			authorityInformationAccess = new AuthorityInformationAccess(
					(ASN1Sequence) new ASN1InputStream(oct.getOctets())
							.readObject());
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		AccessDescription[] accessDescriptions = authorityInformationAccess
				.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {
			LOG.debug("access method: " + accessDescription.getAccessMethod());
			boolean correctAccessMethod = accessDescription.getAccessMethod()
					.equals(accessMethod);
			if (!correctAccessMethod) {
				continue;
			}
			GeneralName gn = accessDescription.getAccessLocation();
			if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
				LOG.debug("not a uniform resource identifier");
				continue;
			}
			DERIA5String str = DERIA5String.getInstance(gn.getDERObject());
			String accessLocation = str.getString();
			LOG.debug("access location: " + accessLocation);
			URI uri = toURI(accessLocation);
			LOG.debug("access location URI: " + uri);
			return uri;
		}
		return null;
	}

	private URI toURI(String str) {
		try {
			URI uri = new URI(str);
			return uri;
		} catch (URISyntaxException e) {
			throw new InvalidParameterException("URI syntax error: "
					+ e.getMessage());
		}
	}

}
