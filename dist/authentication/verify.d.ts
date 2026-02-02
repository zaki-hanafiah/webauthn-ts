import { PublicKeyCredential } from '../models/fido/PublicKeyCredential';
import { ErrorMessage } from '../models/custom/ErrorMessage';
export declare function verify(assertion: PublicKeyCredential, userId: string): ErrorMessage;
