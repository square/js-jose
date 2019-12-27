// Type definitions for jose-jwe-jws
// Project: jose-jwe-jws
// Definitions by: [~YOUR NAME~] <[~A URL FOR YOU~]>

interface IEncryptionResult {
    cipher: ArrayBuffer;
    tag: ArrayBuffer;
}

interface IVerificationResult {
    kid: string;
    verified: boolean;
    payload?: string;
}

type RsaSsaSignAlgorithm = "RS256" | "RS384" | "RS512";
type RsaPssSignAlgorithm = "PS256" | "PS384" | "PS512";
type HmacSignAlgorithm = "HS256" | "HS384" | "HS512";
type EcdsaSignAlgorithm = "ES256" | "ES384" | "ES512";
type SignAlgorithm = RsaSsaSignAlgorithm | RsaPssSignAlgorithm | HmacSignAlgorithm | EcdsaSignAlgorithm;

type RsaOaepEncryptAlgorithm = "RSA-OAEP" | "RSA-OAEP-256";
type AesKwEncryptAlgorithm = "A128KW" | "A256KW";
type AesCbcEncryptAlgorithm = "A128CBC-HS256" | "A256CBC-HS512";
type AesGcmEncryptAlgorithm = "A128GCM" | "A256GCM";
type EncryptAlgorithm = RsaOaepEncryptAlgorithm | AesKwEncryptAlgorithm | AesCbcEncryptAlgorithm | AesGcmEncryptAlgorithm;

type JoseAlgorithm = EncryptAlgorithm | SignAlgorithm;

interface IWebCryptographer {
    new(): IWebCryptographer;
    getContentEncryptionAlgorithm(): EncryptAlgorithm;
    setContentEncryptionAlgorithm(algorithm: EncryptAlgorithm): void;
    getKeyEncryptionAlgorithm(): EncryptAlgorithm;
    setKeyEncryptionAlgorithm(algorithm: EncryptAlgorithm): void;
    getContentSignAlgorithm(): SignAlgorithm;
    setContentSignAlgorithm(algorithm: SignAlgorithm): void;
    createIV(): ArrayBufferView;
    createCek(): PromiseLike<CryptoKey>;
    wrapCek(): PromiseLike<ArrayBuffer>;
    unwrapCek(): PromiseLike<ArrayBuffer>;
    encrypt(iv: Uint8Array, aad: Uint8Array, cek: CryptoKey | PromiseLike<CryptoKey>, plaintext: Uint8Array): PromiseLike<IEncryptionResult>;
    decrypt(cek: CryptoKey | PromiseLike<CryptoKey>, aad: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): PromiseLike<string>;
    sign(aad: Object, payload: string | Object, key: CryptoKey | PromiseLike<CryptoKey>): PromiseLike<ArrayBuffer>;
    verify(aad: string, payload: string, signature: Uint8Array, key: CryptoKey | PromiseLike<CryptoKey>, kid: string): PromiseLike<IVerificationResult>;
}

interface IJsonWebKey {
    kty: string;
    alg?: string;
    kid?: string;
    use?: string;
    key_ops?: string[];
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    "x5t#S256"?: string;
}

interface JWKRSA extends IJsonWebKey {
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

interface IJwkSet {
    keys: IJsonWebKey[];
}

interface IHeaders {
    alg: string;
    jku?: string;
    jwk?: IJsonWebKey;
    kid?: string;
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    'x5t#S256'?: string;
    typ?: string;
    cty?: string;
    crit?: string[];
}

interface IUtils {
    importRsaPublicKey(rsa_key: JWKRSA, alg: JoseAlgorithm): PromiseLike<CryptoKey>;
    importRsaPrivateKey(rsa_key: JWKRSA, alg: JoseAlgorithm): PromiseLike<CryptoKey>;
    importPublicKey(key: IJsonWebKey, alg: JoseAlgorithm): PromiseLike<CryptoKey>;
}

interface IJose {
    Utils: IUtils;
    JoseJWE: IJoseJWE;
    JoseJWS: IJoseJWS
    caniuse(): boolean;
    WebCryptographer: IWebCryptographer;
}

interface ISignedJws {
    header: string;
    protected: string;
    payload: string;
    signature: string;
    JsonSerialize(): Object;
    CompactSerialize(): string;
}

interface ISigner {
    new(cryptographer: IWebCryptographer): ISigner;
    addSigner(pk: CryptoKey, kid: string, aad?: Object, header?: Object): PromiseLike<string>;
    sign(payload: any, aad?: Object, header?: Object): PromiseLike<ISignedJws>;
}

interface IVerifier {
    new(cryptographer: IWebCryptographer, msg: string,
        keyfinder?: (kid: string) => PromiseLike<CryptoKey>): IVerifier;
    addRecipient(pk: CryptoKey | string | JWKRSA, kid?: string, alg?: SignAlgorithm): PromiseLike<string>;
    verify(): PromiseLike<IVerificationResult[]>;
}

interface IJoseJWS {
    Signer: ISigner;
    Verifier: IVerifier;
}

interface IEncrypter {
    new(cryptographer: IWebCryptographer, pubkey: CryptoKey | PromiseLike<CryptoKey>): IEncrypter;
    addHeader(k: string, v: string): void;
    encrypt(plaintext: string): PromiseLike<string>;
}

interface IDecrypter {
    new(cryptographer: IWebCryptographer, key: CryptoKey | PromiseLike<CryptoKey>): IDecrypter;
    decrypt(ciphertext: string): PromiseLike<string>;
}

interface IJoseJWE {
    Encrypter: IEncrypter;
    Decrypter: IDecrypter;
}

interface Window {
    Jose: IJose;
}

declare function setCrypto(cryptoProvider: Crypto): void;
declare const Jose: IJose;
declare var crypto: Crypto;

declare module "jose-jwe-jws" {
    export function setCrypto(cryptoProvider: Crypto): void;
    export const Jose: IJose;
    export var crypto: Crypto;
}
