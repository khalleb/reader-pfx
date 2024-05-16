import forge from 'node-forge';

import { GreetProps, ResultProps } from './types';
import { isNotNull } from './utils';

const decodePfx = (pfxBase64: string, password: string): forge.pkcs12.Pkcs12Pfx => {
  try {
    const p12Der = forge.util.decode64(pfxBase64);
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    return forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
  } catch (error) {
    throw new Error(`Error decoding the PFX file: ${(error as Error).message}`);
  }
};

const extractAndDisplayCertificateValidity = (p12: forge.pkcs12.Pkcs12Pfx): ResultProps => {
  try {
    if (p12 === null || p12 === undefined) {
      throw new Error(`Unable to retrieve certificate data`);
    }

    const safeContent = p12.safeContents.find(k => k.encrypted);

    const serialNumber = safeContent?.safeBags.find(r => r.cert?.serialNumber != null)?.cert?.serialNumber;

    const algorithm = safeContent?.safeBags.find(r => r.cert?.md.algorithm != null)?.cert?.md?.algorithm;

    const commonName = safeContent?.safeBags.find(r => r.cert?.issuer?.attributes?.length != null && r.cert?.issuer?.attributes?.length > 0)?.cert?.issuer.attributes.find(m => m.name === "commonName")?.value as string;

    const validFrom = safeContent?.safeBags.find(r => r.cert?.validity?.notBefore !== null)?.cert?.validity?.notBefore;

    const validUntil = safeContent?.safeBags.find(r => r.cert?.validity?.notAfter !== null)?.cert?.validity?.notAfter;

    const applicantName = safeContent?.safeBags.find(r => r.cert?.subject?.attributes?.length != null && r.cert?.subject?.attributes?.length > 0)?.cert?.subject?.attributes?.find(m => m?.name === "commonName")?.value as string;

    const result: ResultProps = {
      version: p12.version,
      serialNumber: serialNumber,
      algorithm: algorithm,
      issuer: commonName,
      validFrom,
      validUntil,
      applicantName
    };
    return result;

  } catch (error) {
    throw new Error(`${(error as Error).message}`);
  }
};


export function getData(params: GreetProps) {
  if (params === null) {
    throw new Error(`Provide the data`);
  }

  if (!isNotNull(params?.pfxBase64)) {
    throw new Error(`Provide the PFX file`);
  }

  if (!isNotNull(params?.password)) {
    throw new Error(`Provide the PFX file password`);
  }

  const p12 = decodePfx(params?.pfxBase64, params?.password);

  extractAndDisplayCertificateValidity(p12);

}