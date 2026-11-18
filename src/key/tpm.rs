//! TPM 2.0 backend (Linux).
//!
//! The key is an unrestricted ECDSA P-256 signing key under the owner
//! hierarchy's ECC P-256 storage primary. The primary is deterministic, so it
//! is recreated on each use instead of being made persistent. The blob holds
//! the marshalled public area and the TPM-encrypted private area. It is only
//! usable on the TPM that created it.

use anyhow::{Context as _, Result, anyhow, bail};
use p256::ecdsa::Signature;
use ssh_key::sha2::{Digest as _, Sha256};
use std::str::FromStr;
use tss_esapi::{
    Context, TctiNameConf, WrapperErrorKind,
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::KeyHandle,
    interface_types::{
        algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        Digest, EccPoint, EccScheme, Private, Public, PublicBuilder, PublicEccParametersBuilder,
        SignatureScheme, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMT_TK_HASHCHECK,
    utils::PublicKey,
};

const DEFAULT_DEVICE: &str = "/dev/tpmrm0";

pub fn generate() -> Result<Vec<u8>> {
    let mut ctx = connect()?;
    let created = ctx.execute_with_nullauth_session(|ctx| {
        let primary = ctx.create_primary(
            Hierarchy::Owner,
            storage_template()?,
            None,
            None,
            None,
            None,
        )?;
        let created = ctx.create(
            primary.key_handle,
            signing_template()?,
            None,
            None,
            None,
            None,
        );
        ctx.flush_context(primary.key_handle.into())?;
        created
    })?;
    encode_blob(&created.out_public, &created.out_private)
}

pub fn public_key(blob: &[u8]) -> Result<Vec<u8>> {
    let (public, _) = decode_blob(blob)?;
    match PublicKey::try_from(public)? {
        PublicKey::Ecc { x, y } => {
            let mut sec1 = vec![0x04];
            sec1.extend(left_pad::<32>(&x)?);
            sec1.extend(left_pad::<32>(&y)?);
            Ok(sec1)
        }
        PublicKey::Rsa(_) => bail!("the key file holds an RSA key, not a P-256 key"),
    }
}

pub fn sign(blob: &[u8], data: &[u8]) -> Result<Signature> {
    let (public, private) = decode_blob(blob)?;
    let digest = Digest::try_from(Sha256::digest(data).to_vec())?;
    let mut ctx = connect()?;
    let signature = ctx.execute_with_nullauth_session(|ctx| -> Result<_> {
        let primary = ctx.create_primary(Hierarchy::Owner, storage_template()?, None, None, None, None)?;
        let key = ctx.load(primary.key_handle, private, public);
        ctx.flush_context(primary.key_handle.into())?;
        let key: KeyHandle = key.context(
            "the TPM refused the saved key. The TPM was cleared or this key file comes from another machine",
        )?;
        let ticket = TPMT_TK_HASHCHECK { tag: TPM2_ST_HASHCHECK, hierarchy: TPM2_RH_NULL, digest: Default::default() };
        let signature = ctx.sign(key, digest, SignatureScheme::Null, ticket.try_into()?);
        ctx.flush_context(key.into())?;
        Ok(signature?)
    })?;
    let tss_esapi::structures::Signature::EcDsa(ecc) = signature else {
        bail!("the TPM returned a signature that is not ECDSA");
    };
    let r = left_pad::<32>(ecc.signature_r().value())?;
    let s = left_pad::<32>(ecc.signature_s().value())?;
    Ok(Signature::from_scalars(r, s)?)
}

fn connect() -> Result<Context> {
    // TPM2TOOLS_TCTI or TCTI selects another TPM, for example a software TPM.
    match TctiNameConf::from_environment_variable() {
        Ok(tcti) => {
            return Context::new(tcti.clone())
                .with_context(|| format!("cannot connect to the TPM through {tcti:?}"));
        }
        Err(tss_esapi::Error::WrapperError(WrapperErrorKind::ParamsMissing)) => {}
        Err(err) => {
            return Err(err).context("TPM2TOOLS_TCTI or TCTI is not a valid TCTI configuration");
        }
    }
    if let Err(io) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEFAULT_DEVICE)
    {
        if io.kind() == std::io::ErrorKind::PermissionDenied {
            bail!(
                "cannot open {DEFAULT_DEVICE}: permission denied.\n\
                 Add your user to the tss group, then log in again:\n  sudo usermod -aG tss $USER"
            );
        }
        bail!("cannot open {DEFAULT_DEVICE}: {io}. machine-signing needs a TPM 2.0 on Linux");
    }
    let tcti = TctiNameConf::from_str(&format!("device:{DEFAULT_DEVICE}"))?;
    Context::new(tcti).with_context(|| format!("cannot connect to the TPM at {DEFAULT_DEVICE}"))
}

/// The ECC P-256 storage root key template from the TCG provisioning guidance.
fn storage_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

fn signing_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_sign_encrypt(true)
        .build()?;
    let scheme = EccScheme::create(
        EccSchemeAlgorithm::EcDsa,
        Some(HashingAlgorithm::Sha256),
        None,
    )?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, EccCurve::NistP256)
                .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Blob layout: u16 big-endian length of the marshalled public area, the public area, then the private area.
fn encode_blob(public: &Public, private: &Private) -> Result<Vec<u8>> {
    let public = public.marshall()?;
    let mut blob = u16::try_from(public.len())?.to_be_bytes().to_vec();
    blob.extend(public);
    blob.extend(private.value());
    Ok(blob)
}

fn decode_blob(blob: &[u8]) -> Result<(Public, Private)> {
    let malformed = || anyhow!("the key file is damaged");
    let (len, rest) = blob.split_first_chunk::<2>().ok_or_else(malformed)?;
    let len = usize::from(u16::from_be_bytes(*len));
    if rest.len() < len {
        return Err(malformed());
    }
    let (public, private) = rest.split_at(len);
    Ok((
        Public::unmarshall(public)?,
        Private::try_from(private.to_vec())?,
    ))
}

fn left_pad<const N: usize>(bytes: &[u8]) -> Result<p256::FieldBytes> {
    if bytes.len() > N {
        bail!(
            "the TPM returned a {}-byte value for a P-256 coordinate",
            bytes.len()
        );
    }
    let mut out = p256::FieldBytes::default();
    out[N - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}
