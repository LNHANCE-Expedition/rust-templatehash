// SPDX-License-Identifier: CC0-1.0

//! # TemplateHash
//!
//! This crate implements basic support for OP_TEMPLATEHASH as proposed in BIP-???
//! See <https://github.com/instagibbs/bips/blob/bip_op_templatehash/bip-templatehash.md>

use std::ops::Deref;

pub use bitcoin;

/// The BIP redefines OP_SUCCESS187 to push the template hash of the transaction in context onto
/// the stack.
pub use bitcoin::opcodes::all::OP_RETURN_187 as OP_TEMPLATEHASH;

use bitcoin::{
    blockdata::locktime::absolute, consensus::encode::VarInt, consensus::Encodable, io::Write,
    script::PushBytes, transaction::Sequence, transaction::Version, Transaction, TxOut,
};

use bitcoin::hashes::{sha256, sha256t_hash_newtype, Hash};

const ENGINE_EXPECT: &str = "HashEngine::write() never fails";

sha256t_hash_newtype! {
    /// Hash Tag defined in BIP-???
    pub struct TemplateHashTag = hash_str("TemplateHash");

    /// A template hash
    #[hash_newtype(forward)]
    pub struct TemplateHash(_);
}

impl TemplateHash {
    pub fn from_transaction(tx: &Transaction, input_index: u32, annex: Option<&[u8]>) -> Self {
        tx.to_templatehash(input_index, annex)
    }
}

impl AsRef<PushBytes> for TemplateHash {
    fn as_ref(&self) -> &PushBytes {
        self.as_byte_array().into()
    }
}

fn compute_sha_iter<E, T, I>(iter: I) -> sha256::Hash
where
    E: Encodable,
    T: Deref<Target = E>,
    I: IntoIterator<Item = T>,
{
    let mut engine = sha256::Hash::engine();

    for item in iter {
        let _ = (*item).consensus_encode(&mut engine).expect(ENGINE_EXPECT);
    }

    sha256::Hash::from_engine(engine)
}

/// Compute sha_sequences as defined in bip-0341
pub fn sha_sequences<S, I>(iter: I) -> sha256::Hash
where
    S: Deref<Target = Sequence>,
    I: IntoIterator<Item = S>,
{
    compute_sha_iter(iter)
}

/// Compute sha_outputs as defined in bip-0341
pub fn sha_outputs<O, I>(iter: I) -> sha256::Hash
where
    O: Deref<Target = TxOut>,
    I: IntoIterator<Item = O>,
{
    compute_sha_iter(iter)
}

/// Compute sha_annex as defined in bip-0341
///
/// The provided annex must include the 0x50 annex prefix byte
pub fn sha_annex(annex: &[u8]) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    let annex_len: VarInt = annex.len().into();

    let _ = annex_len
        .consensus_encode(&mut engine)
        .expect(ENGINE_EXPECT);

    engine.write_all(annex).expect(ENGINE_EXPECT);

    sha256::Hash::from_engine(engine)
}

/// Represents a transaction from which a template can be generated
///
/// Intended as a convenience so that users don't need to provide dummy values for data that
/// TEMPLATEHASH does not commit to
pub struct TransactionTemplate {
    pub version: Version,
    pub lock_time: absolute::LockTime,
    pub sequences: Vec<Sequence>,
    pub outputs: Vec<TxOut>,
}

impl TransactionTemplate {
    /// Calculate a template hash from a transaction template, for a given input
    pub fn templatehash(&self, input_index: u32, annex: Option<&[u8]>) -> TemplateHash {
        self.to_templatehash(input_index, annex)
    }
}

pub trait ToTemplateHash {
    /// Calculate a template hash
    ///
    /// ```
    /// use bitcoin::opcodes::all::{OP_EQUALVERIFY};
    /// use bitcoin::{Amount, blockdata::locktime::absolute, ScriptBuf, Sequence, transaction::Version,
    /// TxOut};
    /// use templatehash::{OP_TEMPLATEHASH, ToTemplateHash, TransactionTemplate};
    ///
    /// let outputs = vec![
    ///     TxOut {
    ///         value: Amount::from_sat(424242),
    ///         script_pubkey: ScriptBuf::new_op_return(*b"hello, world"),
    ///     },
    ///     TxOut {
    ///         value: Amount::from_sat(42),
    ///         script_pubkey: ScriptBuf::new_op_return(*b"goodbye, world"),
    ///     },
    /// ];
    ///
    /// let template = TransactionTemplate {
    ///     version: Version::TWO,
    ///     lock_time: absolute::LockTime::ZERO,
    ///     sequences: vec![Sequence::ZERO, Sequence::from_height(42)],
    ///     outputs,
    /// };
    ///
    /// let templatehash = template.to_templatehash(1, None);
    ///
    /// // This usage is very similar to OP_CHECKTEMPLATEVERIFY
    /// let script_committing_to_template = {
    ///     let mut script = ScriptBuf::new();
    ///     script.push_opcode(OP_TEMPLATEHASH);
    ///     script.push_slice(templatehash);
    ///     script.push_opcode(OP_EQUALVERIFY);
    ///     script
    /// };
    fn to_templatehash(self, input_index: u32, annex: Option<&[u8]>) -> TemplateHash;
}

impl ToTemplateHash for &Transaction {
    fn to_templatehash(self, input_index: u32, annex: Option<&[u8]>) -> TemplateHash {
        debug_assert!((input_index as usize) < self.input.len());

        templatehash(
            self.version,
            self.lock_time,
            sha_sequences(self.input.iter().map(|input| &input.sequence)),
            sha_outputs(&self.output),
            input_index,
            annex.map(sha_annex),
        )
    }
}

impl ToTemplateHash for &TransactionTemplate {
    fn to_templatehash(self, input_index: u32, annex: Option<&[u8]>) -> TemplateHash {
        debug_assert!((input_index as usize) < self.sequences.len());

        templatehash(
            self.version,
            self.lock_time,
            sha_sequences(&self.sequences),
            sha_outputs(&self.outputs),
            input_index,
            annex.map(sha_annex),
        )
    }
}

/// Calculate a template hash from the components of a transaction template, for a given input
pub fn templatehash(
    version: Version,
    lock_time: absolute::LockTime,
    sha_sequences: sha256::Hash,
    sha_outputs: sha256::Hash,
    input_index: u32,
    sha_annex: Option<sha256::Hash>,
) -> TemplateHash {
    let mut engine = TemplateHash::engine();

    version.consensus_encode(&mut engine).expect(ENGINE_EXPECT);
    lock_time
        .consensus_encode(&mut engine)
        .expect(ENGINE_EXPECT);

    sha_sequences
        .consensus_encode(&mut engine)
        .expect(ENGINE_EXPECT);

    sha_outputs
        .consensus_encode(&mut engine)
        .expect(ENGINE_EXPECT);

    let annex_present = sha_annex.is_some() as u8;

    annex_present
        .consensus_encode(&mut engine)
        .expect(ENGINE_EXPECT);

    input_index
        .consensus_encode(&mut engine)
        .expect(ENGINE_EXPECT);

    if let Some(sha_annex) = sha_annex {
        sha_annex
            .consensus_encode(&mut engine)
            .expect(ENGINE_EXPECT);
    }

    TemplateHash::from_engine(engine)
}
