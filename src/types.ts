export interface GreetProps {
  pfxBase64: string;
  password: string;
}

export interface ResultProps {
  version?: string;
  serialNumber?: string;
  algorithm?: string;
  issuer?: string;
  validFrom: Date | undefined;
  validUntil: Date | undefined;
  applicantName?: string;
}