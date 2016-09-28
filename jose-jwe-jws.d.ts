export interface EncryptionResult {
    cipher: ArrayBuffer;
    tag: ArrayBuffer;
}

export interface VerificationResult {
    kid: string;
    verified: boolean;
    payload?: string;
}

export interface WebCryptographer {
    new(): WebCryptographer;
    setKeyEncryptionAlgorithm(algo: string):void;
    setContentSignAlgorithm(algo: string):void;
    createIV():ArrayBufferView;
    createCek():PromiseLike<CryptoKey>;
    wrapCek():PromiseLike<ArrayBuffer>;
    unwrapCek():PromiseLike<ArrayBuffer>;
    encrypt(iv: Uint8Array, aad: Uint8Array, cek: CryptoKey|PromiseLike<CryptoKey>, plaintext: Uint8Array):PromiseLike<EncryptionResult>;
    decrypt(cek: CryptoKey|PromiseLike<CryptoKey>, aad: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array):PromiseLike<string>;
    sign(aad: Object, payload: string|Object, key:CryptoKey|PromiseLike<CryptoKey>):PromiseLike<ArrayBuffer>;
    verify(aad: string, payload: string, signature: Uint8Array, key: CryptoKey|PromiseLike<CryptoKey>, kid: string):PromiseLike<VerificationResult>;
}

export interface JsonWebKey {
    kty: string;
    alg?: string;
    kid?: string;
    use?: string;
    key_ops?: string[];
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    'x5t#S256'?: string;
}

export interface JWKRSA extends JsonWebKey {
    n?: string;
    e?: string;
    d?: string;
    p?: string;
    q?: string;
    dp?: string;
    dq?: string;
    qi?: string;
    oth?: {
        r: string;
        d: string;
        t: string;
    }[];
}

export interface JwkSet {
    keys: JsonWebKey[];
}

export interface Headers {
    alg: string;
    jku?: string;
    jwk?: JsonWebKey;
    kid?: string;
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    'x5t#S256'?: string;
    typ?: string;
    cty?: string;
    crit?: string[];
}

export interface Utils {
    importRsaPublicKey(rsa_key: JWKRSA, alg: string): PromiseLike<CryptoKey>;
    importRsaPrivateKey(rsa_key: JWKRSA, alg: string): PromiseLike<CryptoKey>;
}

export interface Jose {
    Utils: Utils;
    caniuse():boolean;
    WebCryptographer:WebCryptographer;
}

export interface SignedJws {
    header: string;
    protected: string;
    payload: string;
    signature: string;
    JsonSerialize(): Object;
    CompactSerialize(): string;
}

export interface Signer {
    new(cryptographer: WebCryptographer):Signer;
    addSigner(pk: CryptoKey, kid: string, aad?: Object, header?: Object):PromiseLike<string>;
    sign(payload: any, aad?: Object, header?: Object):PromiseLike<SignedJws>;
}

export interface Verifier {
    new(cryptographer: WebCryptographer, msg: string,
        keyfinder?: (kid: string) => PromiseLike<CryptoKey>):Verifier;
    addRecipient(pk: CryptoKey|string|JWKRSA, kid?: string, alg?: string):PromiseLike<string>;
    verify(): PromiseLike<VerificationResult[]>;
}

export interface JoseJWS {
    Signer:Signer;
    Verifier:Verifier;
}

export interface Encrypter {
    new(cryptographer: WebCryptographer, pubkey: CryptoKey|PromiseLike<CryptoKey>):Encrypter;
    addHeader(k: string, v: string):void;
    encrypt(plaintext: string):PromiseLike<string>;
}

export interface Decrypter {
    new(cryptographer: WebCryptographer, key: CryptoKey|PromiseLike<CryptoKey>):Decrypter;
    decrypt(ciphertext: string):PromiseLike<string>;
}

export interface JoseJWE {
    Encrypter:Encrypter;
    Decrypter:Decrypter;
}

export interface setCrypto {
    (cryptoProvider: any): any;
}

export var setCrypto: setCrypto;
export var Jose: Jose;
export var JoseJWE: JoseJWE;
export var JoseJWS: JoseJWS;
