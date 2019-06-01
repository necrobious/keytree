use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{self as aead, Nonce, Key as AeadKey, Tag as AeadTag};
use sodiumoxide::crypto::sign::ed25519::{self, PublicKey, SecretKey, Seed};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::auth::hmacsha512256::{self, Tag as HmacTag, Key as HmacKey};
use trustchain::v2::{TrustChain, TrustError};
use cachet::v1::{Cachet,CachetError};
use nom::{do_parse, take, map_opt, length_data, named, be_u16, be_u32, tag, verify};
use byteorder::{BigEndian, WriteBytesExt};
use std::fmt;

#[derive(PartialEq)] // TODO: does this need to be time-constant comparison?!!
pub enum KeyTree {
    Root   {key:AeadKey, skey:SecretKey, chain:TrustChain},
    Second {key:AeadKey, skey:SecretKey, chain:TrustChain},
    Third  {key:AeadKey, skey:SecretKey, chain:TrustChain},
    Fourth {key:AeadKey, skey:SecretKey, chain:TrustChain},
    Fith   {key:AeadKey, skey:SecretKey, chain:TrustChain},
}

impl fmt::Debug for KeyTree {
    fn fmt (&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "KeyTree[ generation:{}; chain: {} ]", self.generation(), self.chain())
    }
}

#[derive(Copy,Clone,Debug,PartialEq)]
pub enum KeyTreeError {
    MaxDerivationExceeded,
    TrustChainComparisonFailure,
    TrustError(TrustError),
    CachetError(CachetError),
    PayloadDecryptionError,
    PayloadDecryptionParseError,
}

named!(encrypted_payload<(Nonce, AeadTag, &[u8])>, do_parse!(
    _tag: tag!(b"KT") >>
    _ver: verify!(be_u16, |ver:u16| ver == 1) >>
    iv:  map_opt!(take!(24), |iv_bytes:&[u8] | aead::Nonce::from_slice(iv_bytes)) >>
    tag: map_opt!(take!(16), |tag_bytes:&[u8]| aead::Tag::from_slice(tag_bytes)) >>
    data: length_data!(be_u32) >>
    ( (iv,tag,data) )
));

impl KeyTree {
    fn generation(&self) -> usize {
        match self {
            KeyTree::Root   {..} => 1,
            KeyTree::Second {..} => 2,
            KeyTree::Third  {..} => 3,
            KeyTree::Fourth {..} => 4,
            KeyTree::Fith   {..} => 5,
        }
    }

    fn key(&self) -> &AeadKey {
        match self {
            KeyTree::Root   {key,..} => key,
            KeyTree::Second {key,..} => key,
            KeyTree::Third  {key,..} => key,
            KeyTree::Fourth {key,..} => key,
            KeyTree::Fith   {key,..} => key,
        }
    }

    fn skey(&self) -> &SecretKey {
        match self {
            KeyTree::Root   {skey,..} => skey,
            KeyTree::Second {skey,..} => skey,
            KeyTree::Third  {skey,..} => skey,
            KeyTree::Fourth {skey,..} => skey,
            KeyTree::Fith   {skey,..} => skey,
        }
    }

    fn chain(&self) -> &TrustChain {
        match self {
            KeyTree::Root   {chain,..} => chain,
            KeyTree::Second {chain,..} => chain,
            KeyTree::Third  {chain,..} => chain,
            KeyTree::Fourth {chain,..} => chain,
            KeyTree::Fith   {chain,..} => chain,
        }
    }

    // The only public means of creating a KeyTree is from a root key secret.
    // All other variations of the KeyTree enum should be derived from the root key.
    pub fn from_root (root_key:AeadKey) -> Result<KeyTree,KeyTreeError> {
        let (pkey, skey) = ed25519::keypair_from_seed(&Seed(root_key.0));
        let chain =
            TrustChain::root_only_chain(pkey, Box::new(vec!(pkey)))
                .map_err(|e| KeyTreeError::TrustError(e))?;

        Ok(KeyTree::Root{ key:root_key, skey: skey, chain: chain})
    }

    pub fn derive_key(&self, derivation_context: &[u8;32]) -> Result<KeyTree, KeyTreeError> {
        // length of the namespace is variable, to get it into a fixed size [u8;32] well
        // digest it.
        // grab my own public key
        let pkey = self.chain().end_key().0;
        // concat the digested namespace with my public key, then digest the result
        // to derive out salt for deriving our new key.
        let sha256::Digest(hkdf_salt) = sha256::hash(&concat_arrays(derivation_context,&pkey));
        // get our derived aead key, verify key, and signing key
        let (d_key, d_pkey, d_skey) = derive_key(&self.key().0, &hkdf_salt, derivation_context);

        let d_pkey_sig = ed25519::sign_detached(&d_pkey.0, &self.skey());

        // We need trust-chain's ability to append in lockstep with each derivation, if we can
        // not extend the trust chain, then we can not derive further.
        let d_chain = self.chain().append(d_pkey.clone(), d_pkey_sig).map_err( |e|
            match e {
                TrustError::MaxChainLengthExceeded => KeyTreeError::MaxDerivationExceeded,
                _ => KeyTreeError::TrustError(e)
            }
        )?;

        //TODO:: Look into fail-fast at top of this method if self is KeyTree::Fith. Would that
        //       open this method up to a timing attack? I don't think so, but need to look closer.
        match self {
            KeyTree::Root   {..} => Ok(KeyTree::Second {key:d_key, skey:d_skey, chain:d_chain}),
            KeyTree::Second {..} => Ok(KeyTree::Third  {key:d_key, skey:d_skey, chain:d_chain}),
            KeyTree::Third  {..} => Ok(KeyTree::Fourth {key:d_key, skey:d_skey, chain:d_chain}),
            KeyTree::Fourth {..} => Ok(KeyTree::Fith   {key:d_key, skey:d_skey, chain:d_chain}),
            KeyTree::Fith   {..} => Err(KeyTreeError::MaxDerivationExceeded),
        }
    }

    pub fn encrypt (&self, data_to_encrypt:&[u8]) -> Result<Cachet,KeyTreeError> {
        let iv = aead::gen_nonce();
        let aad = self.chain().as_bytes();
        let mut data  = Vec::with_capacity(data_to_encrypt.len());
        for byte in data_to_encrypt {data.push(*byte);}
        let AeadTag(tag_bytes) = aead::seal_detached(data.as_mut_slice(), Some(&aad), &iv, self.key()); // [u8;16]
        let Nonce(iv_bytes) = iv; // [u8;24]
        let encrypted_data = asemble_encrypted_payload(&iv_bytes,&tag_bytes,&data);
        Cachet::new(encrypted_data, self.chain(), self.skey()).map_err(|e| KeyTreeError::CachetError(e))
    }

    pub fn decrypt (&self, cachet: Cachet) -> Result<Vec<u8>, KeyTreeError> {
        if cachet.trust_chain() != *self.chain() {
            return Err(KeyTreeError::TrustChainComparisonFailure)
        }
        let aad = self.chain().as_bytes();
        let cachet_payload = cachet.data();
        let (_, (iv, tag, enc_data)) = encrypted_payload(&cachet_payload).map_err(|_| KeyTreeError::PayloadDecryptionParseError)?;
        let mut data = Vec::with_capacity(enc_data.len());
        for byte in enc_data {data.push(*byte);}
        aead::open_detached(data.as_mut_slice(), Some(&aad),&tag,&iv,self.key())
            .map_err(|_| KeyTreeError::PayloadDecryptionError)
            .map(|_| data)
    }

    pub fn derive_and_encrypt (&self, derivation_context: &[u8;32], data_to_encrypt:&[u8]) -> Result<Cachet,KeyTreeError> {
        let child = self.derive_key(&derivation_context)?;
        child.encrypt(data_to_encrypt)
    }

    pub fn derive_and_decrypt (&self, derivation_context: &[u8;32], cachet: Cachet) -> Result<Vec<u8>, KeyTreeError> {
        let child = self.derive_key(&derivation_context)?;
        child.decrypt(cachet)
    }
}

fn asemble_encrypted_payload <'a> (aead_iv: &'a [u8;24], aead_tag: &'a [u8;16], encrypted_data: &'a [u8]) -> Vec<u8> {
    let mut header:Vec<u8> = [0x4B,0x54,0x00,0x01].to_vec();
    let mut data  = Vec::with_capacity(
        2  + // Tag = "KT"
        2  + // Version u16, 2 bytes
        24 + // XChaCha20-Poly1305-IETF Nonce/IV, 24 vytes
        16 + // XChaCha20-Poly1305-IETF AEAD Tag, 16 bytes
        4  + // encrypted data length, u32, 4 bytes
        encrypted_data.len()); // Encrypted Data, N bytes
    data.append(&mut header);
    for byte in aead_iv  { data.push(*byte) } // 24 bytes
    for byte in aead_tag { data.push(*byte) } // 16 bytes
    data.write_u32::<BigEndian>(encrypted_data.len() as u32).unwrap(); // 4 bytes
    for byte in encrypted_data { data.push(*byte) }
    data
}

// rfc5869  compatible hkdf using sha512-256 on a fixed 32 byte input size
// which means only one round of 'expand' defined in 2.3 is needed for our usecase.
fn hkdf <'a> (input_key_material: &'a[u8;32], salt: &'a[u8;32], info: &'a[u8;32]) -> [u8;32] {
    // rfc5869 2.2
    let HmacTag(pseudo_random_key) = hmacsha512256::authenticate(
        input_key_material, // ikm as hmac data
        &HmacKey(*salt)  // salt as hmac key
    );

    // rfc5869 2.3 concat T(0) | info | 0x01 (counter byte)
    let info_with_counter =                   // T(0) empty string (zero length)
        [info[ 0],info[ 1],info[ 2],info[ 3], //-+
         info[ 4],info[ 5],info[ 6],info[ 7], // |
         info[ 8],info[ 9],info[10],info[11], // |
         info[12],info[13],info[14],info[15], // | Info
         info[16],info[17],info[18],info[19], // |
         info[20],info[21],info[22],info[23], // |
         info[24],info[25],info[26],info[27], // |
         info[28],info[29],info[30],info[31], //-+
                                       0x01]; // counter byte

    // rfc5869 2.3 one round, since output size matches input
    let HmacTag(t1) = hmacsha512256::authenticate(
        //&[0x01], // no info,
        &info_with_counter, // no info,
        &HmacKey(pseudo_random_key),
    );
    t1
}

// current version of sodiumoxide does not yet export the KDF API
// that is available in newer versions of libsodium. We'll abstract ths for now.
// once the KDF API is available, this can probably go away.
// TODO: verify crypto safty/sanity of using an AEAD key as Ed25519 seed.
fn derive_key <'a> (input_key_material: &'a [u8;32], salt: &'a [u8;32], info: &'a [u8;32]) -> (AeadKey, PublicKey, SecretKey) {
    let new_key_bytes = hkdf(input_key_material, salt, info);
    let (verify_material, sign_material) = ed25519::keypair_from_seed(&Seed(new_key_bytes));
    (AeadKey(new_key_bytes), verify_material, sign_material)
}

fn concat_arrays <'a> (l: &'a [u8;32], r: &'a [u8;32]) -> [u8;64] {
    [l[ 0], l[ 1], l[ 2], l[ 3], l[ 4], l[ 5], l[ 6], l[ 7],
     l[ 8], l[ 9], l[10], l[11], l[12], l[13], l[14], l[15],
     l[16], l[17], l[18], l[19], l[20], l[21], l[22], l[23],
     l[24], l[25], l[26], l[27], l[28], l[29], l[30], l[31],
     r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
     r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
     r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
     r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31]]
}


