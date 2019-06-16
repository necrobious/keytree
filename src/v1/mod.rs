mod keytree;

pub use self::keytree::*;


#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{self as aead};//, Key as AeadKey};
    use sodiumoxide::crypto::hash::sha256::{self as hash};
    use sodiumoxide::crypto::pwhash::argon2id13::{self as pbkdf};
    use super::keytree::{KeyTree, KeyTreeError};

    #[test]
    fn root_from_password_should_work () {
        let passwd_salt = pbkdf::gen_salt();
        let passwd = "sekrit password";

        let root_keytree_res = super::root_from_password(
            passwd.as_bytes(),
            &passwd_salt.0
        );

        assert!(root_keytree_res.is_ok());

    }

    #[test]
    fn encrypted_root_from_password_should_work () {
        let root_key = aead::gen_key();
        let root_nonce = aead::gen_nonce();
        let passwd_salt = pbkdf::gen_salt();
        let passwd = "sekrit password";

        let mut passwd_key_bytes = [0u8;aead::KEYBYTES]; // 32 bytes

        let passwd_key_derive_res = pbkdf::derive_key(
            &mut passwd_key_bytes,
            passwd.as_bytes(),
            &passwd_salt,
            pbkdf::OPSLIMIT_SENSITIVE,
            pbkdf::MEMLIMIT_SENSITIVE
        );

        assert!(passwd_key_derive_res.is_ok());

        let passwd_key_res = aead::Key::from_slice(&passwd_key_bytes);
        assert!(passwd_key_res.is_some());
        let passwd_key = passwd_key_res.unwrap();

        let mut buf = Vec::with_capacity(root_key.0.len());
        for b in root_key.0.iter() { buf.push(*b); }

        let root_tag = aead::seal_detached(&mut buf, None, &root_nonce, &passwd_key);

        let aad = [0u8;0];

        let root_keytree_res = super::root_from_encrypted_password(
            &buf,
            &aad,
            &root_nonce.0,
            &root_tag.0,
            passwd.as_bytes(),
            &passwd_salt.0
        );

        assert!(root_keytree_res.is_ok());

    }

    #[test]
    fn root_keytree_should_construct () {
        let k = aead::gen_key();
        let root_res = KeyTree::from_root(k);

        assert!(root_res.is_ok());

        let root = root_res.unwrap();
        let sec_data = b"super secret";
        let enc_res = root.encrypt(sec_data);

        assert!(enc_res.is_ok());

        let cachet = enc_res.unwrap();
        //let cachet_bytes = cachet.as_bytes();
        let dec_res = root.decrypt(&cachet);

        assert!(dec_res.is_ok());

        let dec = dec_res.unwrap();

        assert_eq!(dec,sec_data);
    }

    #[test]
    fn derivation_should_work () {
        let k = aead::gen_key();
        let root_res = KeyTree::from_root(k);

        assert!(root_res.is_ok());

        let root = root_res.unwrap();

        let sec_data = b"super secret";

        let hash::Digest(sec_data_hash) = hash::hash(sec_data);

        let child_derive_res = root.derive_key(&sec_data_hash);

        assert!(child_derive_res.is_ok());

        let child = child_derive_res.unwrap();

        let encrypt_res = child.encrypt(sec_data);

        assert!(encrypt_res.is_ok());

        let cachet = encrypt_res.unwrap();

        let decrypt_res = child.decrypt(&cachet);

        assert!(decrypt_res.is_ok());

        let decrypt_data = decrypt_res.unwrap();

        assert_eq!(decrypt_data,sec_data);
    }

    #[test]
    fn derive_and_encrypt_should_work () {
        let k = aead::gen_key();
        let root_res = KeyTree::from_root(k);

        assert!(root_res.is_ok());

        let root = root_res.unwrap();

        let sec_data = b"super secret";

        let hash::Digest(sec_data_hash) = hash::hash(sec_data);

        let encrypt_res = root.derive_and_encrypt(&sec_data_hash, sec_data);

        assert!(encrypt_res.is_ok());

        let cachet = encrypt_res.unwrap();

        let decrypt_res = root.derive_and_decrypt(&sec_data_hash, &cachet);

        assert!(decrypt_res.is_ok());

        let decrypt_data = decrypt_res.unwrap();

        assert_eq!(decrypt_data,sec_data);
    }

    fn gen_random_context () -> [u8;32] {
        // we'll just use random keys for our derivation-contexts.
        let aead::Key(random_context) = aead::gen_key();
        random_context
    }

    #[test]
    fn key_derivation_should_fail_past_fith_generation () {
        let k = aead::gen_key();
        let root_res = KeyTree::from_root(k);

        assert!(root_res.is_ok());

        let root = root_res.unwrap();

        let second_ctx = gen_random_context();
        let third_ctx  = gen_random_context();
        let fourth_ctx = gen_random_context();
        let fith_ctx   = gen_random_context();
        let sixth_ctx  = gen_random_context();

        let second_res = root.derive_key(&second_ctx);
        assert!(second_res.is_ok());
        let second = second_res.unwrap();

        let third_res = second.derive_key(&third_ctx);
        assert!(third_res.is_ok());
        let third = third_res.unwrap();

        let fourth_res = third.derive_key(&fourth_ctx);
        assert!(fourth_res.is_ok());
        let fourth = fourth_res.unwrap();

        let fith_res = fourth.derive_key(&fith_ctx);
        assert!(fith_res.is_ok());
        let fith = fith_res.unwrap();

        let sixth_res = fith.derive_key(&sixth_ctx);
        assert_eq!(sixth_res, Err(KeyTreeError::MaxDerivationExceeded));
    }
}
