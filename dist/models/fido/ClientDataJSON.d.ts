export interface ClientDataJSON {
    challenge: string;
    origin: string;
    type: 'webauthn.create' | 'webauthn.get';
    tokenBinding?: {
        status: 'supported' | 'present';
        id: string;
    };
}
