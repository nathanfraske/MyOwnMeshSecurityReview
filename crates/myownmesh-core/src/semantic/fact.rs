//! Canonical fact identities and signed semantic content.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::content::{Encoder, FactBody, FactDomain};
use super::verify::SemanticError;

/// The digest of canonical fact content.  It is the only identity used by the
/// causal graph; envelopes and couriers cannot create a second identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FactId([u8; 32]);

impl FactId {
    pub fn from_content(content: &FactContent) -> Self {
        let digest = Sha256::digest(content.canonical_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_lowercase()
    }
}

impl std::fmt::Debug for FactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FactId").field(&self.base32()).finish()
    }
}

impl std::fmt::Display for FactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.base32())
    }
}

impl Serialize for FactId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for FactId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded != encoded.to_lowercase() {
            return Err(D::Error::custom("FactId must use lowercase base32"));
        }
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("FactId must decode to 32 bytes"));
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes);
        let id = Self(value);
        if encoded != id.base32() {
            return Err(D::Error::custom("FactId is not canonical base32"));
        }
        Ok(id)
    }
}

/// The signed, transport-independent content of a V4 semantic fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactContent {
    /// Explicit wire-carried version. Only V4 semantic content is admitted.
    pub version: u32,
    pub domain: FactDomain,
    pub mesh_context: String,
    pub body: FactBody,
    pub author: String,
    pub parents: Vec<FactId>,
}

impl FactContent {
    pub fn new(
        domain: FactDomain,
        mesh_context: impl Into<String>,
        body: FactBody,
        author: impl Into<String>,
        mut parents: Vec<FactId>,
    ) -> Self {
        parents.sort();
        parents.dedup();
        let mut body = body;
        body.normalize();
        Self {
            version: super::SEMANTIC_SCHEMA_VERSION,
            domain,
            mesh_context: mesh_context.into(),
            body,
            author: author.into(),
            parents,
        }
    }

    pub fn open_participation(
        mesh_context: impl Into<String>,
        device_id: impl Into<String>,
        joined: bool,
        label: impl Into<String>,
        parents: Vec<FactId>,
    ) -> Self {
        let device_id = device_id.into();
        Self::new(
            FactDomain::Participation,
            mesh_context,
            FactBody::OpenParticipation {
                device_id: device_id.clone(),
                joined,
                label: label.into(),
            },
            device_id,
            parents,
        )
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Encoder::new();
        out.tag("myownmesh-semantic-v4");
        out.tag("schema");
        out.bytes(&self.version.to_be_bytes());
        out.tag(self.domain.tag());
        out.text(&self.mesh_context);
        out.text(&self.author);
        out.tag("parents");
        out.list_ids(&self.parents);
        out.tag("body");
        self.body.encode(&mut out);
        out.finish()
    }

    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.version != super::SEMANTIC_SCHEMA_VERSION {
            return Err(SemanticError::UnsupportedVersion(self.version));
        }
        if self.mesh_context.is_empty() {
            return Err(SemanticError::EmptyField("mesh_context"));
        }
        if self.author.is_empty() {
            return Err(SemanticError::EmptyField("author"));
        }
        if self.body.domain() != self.domain {
            return Err(SemanticError::DomainMismatch);
        }
        self.body.validate_canonical()?;
        for pair in self.parents.windows(2) {
            if pair[0] == pair[1] {
                return Err(SemanticError::DuplicateParent);
            }
            if pair[0] > pair[1] {
                return Err(SemanticError::UnsortedParents);
            }
        }
        match &self.body {
            FactBody::OpenParticipation { device_id, .. }
            | FactBody::SelfStandDown { device_id, .. } => {
                if crate::signing::pubkey_part(&self.author)
                    != crate::signing::pubkey_part(device_id)
                {
                    return Err(SemanticError::InvalidOpenAuthor);
                }
            }
            FactBody::Attestation { signer, .. } => {
                if crate::signing::pubkey_part(&self.author) != crate::signing::pubkey_part(signer)
                {
                    return Err(SemanticError::AuthorMismatch);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct WireFactContent {
    version: u32,
    domain: FactDomain,
    mesh_context: String,
    body: FactBody,
    author: String,
    parents: Vec<FactId>,
}

impl<'de> Deserialize<'de> for FactContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireFactContent::deserialize(deserializer)?;
        let content = Self {
            version: wire.version,
            domain: wire.domain,
            mesh_context: wire.mesh_context,
            body: wire.body,
            author: wire.author,
            parents: wire.parents,
        };
        content.validate().map_err(D::Error::custom)?;
        Ok(content)
    }
}

/// A canonical fact plus a signature over its content-derived FactId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFact {
    pub content: FactContent,
    pub id: FactId,
    pub signature: String,
}

impl SignedFact {
    pub fn sign(content: FactContent, key: &SigningKey) -> Result<Self, SemanticError> {
        content.validate()?;
        let expected_author = BASE32_NOPAD
            .encode(key.verifying_key().as_bytes())
            .to_lowercase();
        if crate::signing::pubkey_part(&content.author) != expected_author {
            return Err(SemanticError::AuthorMismatch);
        }
        let id = FactId::from_content(&content);
        let signature = crate::signing::sign_with(key, id.as_bytes());
        Ok(Self {
            content,
            id,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), SemanticError> {
        super::verify::verify_fact(self)
    }
}

/// Alias used by adapters when they need to state that a value is canonical.
pub type CanonicalFact = SignedFact;
