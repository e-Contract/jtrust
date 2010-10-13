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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import be.fedict.trust.CertificateConstraint;

/**
 * QCStatements certificate constraint.
 * 
 * @author Frank Cornelis
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3039.txt">RFC 3039</a>
 */
public class QCStatementsCertificateConstraint implements CertificateConstraint {

	private static final Log LOG = LogFactory
			.getLog(QCStatementsCertificateConstraint.class);

	private final Boolean qcComplianceFilter;

	public QCStatementsCertificateConstraint(Boolean qcComplianceFilter) {
		this.qcComplianceFilter = qcComplianceFilter;
	}

	public boolean check(X509Certificate certificate) {
		byte[] extensionValue = certificate
				.getExtensionValue(X509Extensions.QCStatements.getId());
		if (null == extensionValue) {
			return false;
		}
		ASN1Sequence qcStatements;
		try {
			DEROctetString oct = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(extensionValue)).readObject());
			qcStatements = (ASN1Sequence) new ASN1InputStream(oct.getOctets())
					.readObject();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		Enumeration<?> qcStatementEnum = qcStatements.getObjects();
		boolean qcCompliance = false;
		while (qcStatementEnum.hasMoreElements()) {
			QCStatement qcStatement = QCStatement.getInstance(qcStatementEnum
					.nextElement());
			DERObjectIdentifier statementId = qcStatement.getStatementId();
			LOG.debug("statement Id: " + statementId.getId());
			if (QCStatement.id_etsi_qcs_QcCompliance.equals(statementId)) {
				qcCompliance = true;
			}
		}
		if (null != this.qcComplianceFilter) {
			if (qcCompliance != this.qcComplianceFilter) {
				return false;
			}
		}
		return true;
	}
}
