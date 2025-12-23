export interface JSONWebKey {
    kty: string
    // RSA fields
    n?: string
    e?: string
    // EC fields
    crv?: string
    x?: string
    y?: string
}
// __afill_20251223_2031__
