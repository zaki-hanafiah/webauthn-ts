/// <reference types="node" />
/// <reference types="node" />
export declare function parseAuthenticatorData(authData: Buffer): any;
export declare function generatePublicKeyCredentialCreationOptions(): {
    challenge: string;
    rp: {
        name: string | undefined;
        id: string | undefined;
    };
    user: {
        id: string;
        name: string;
        displayName: string;
    };
    pubKeyCredParams: {
        alg: number;
        type: string;
    }[];
    authenticatorSelection: {
        requireResidentKey: boolean;
        userVerification: string;
    };
    timeout: number;
    attestation: string;
};
export declare function testCreateCreds(): {
    attestation: string;
    authenticatorSelection: {
        requireResidentKey: boolean;
        userVerification: string;
    };
    challenge: string;
    pubKeyCredParams: {
        type: string;
        alg: number;
    }[];
    rp: {
        id: string | undefined;
        name: string | undefined;
    };
    timeout: number;
    user: {
        id: string;
        name: string;
        displayName: string;
    };
};
export declare function generatePublicKeyCredentialRequestOptions(userId: string): {
    challenge: string;
    timeout: number;
    rpId: string | undefined;
    allowCredentials: {
        type: string;
        id: string;
    }[];
};
export declare function coseToJwk(cose: any): {};
export declare function sha256(data: any): Buffer;
export declare function parseCertInfo(certInfoBuffer: Buffer): {
    magic: number;
    type: any;
    qualifiedSigner: Buffer;
    extraData: Buffer;
    clockInfo: {
        clock: Buffer;
        resetCount: number;
        restartCount: number;
        safe: boolean;
    };
    firmwareVersion: Buffer;
    attested: {
        nameAlg: any;
        name: Buffer;
        qualifiedName: Buffer;
    };
};
export declare function parsePubArea(pubAreaBuffer: Buffer): {
    type: any;
    nameAlg: any;
    objectAttributes: {
        fixedTPM: boolean;
        stClear: boolean;
        fixedParent: boolean;
        sensitiveDataOrigin: boolean;
        userWithAuth: boolean;
        adminWithPolicy: boolean;
        noDA: boolean;
        encryptedDuplication: boolean;
        restricted: boolean;
        decrypt: boolean;
        signORencrypt: boolean;
    };
    authPolicy: Buffer;
    parameters: {
        symmetric: any;
        scheme: any;
        keyBits: number;
        exponent: number;
        curveID?: undefined;
        kdf?: undefined;
    } | {
        symmetric: any;
        scheme: any;
        curveID: any;
        kdf: any;
        keyBits?: undefined;
        exponent?: undefined;
    };
    unique: Buffer;
};
export declare function ecdaaWarning(): void;
export declare function algorithmWarning(alg: number | string): void;
