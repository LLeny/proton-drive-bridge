use crate::errors::ErrorCode;
use base64::{Engine, prelude::BASE64_STANDARD};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_aux::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[allow(clippy::ref_option)]
pub fn to_option_base64<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = v.as_ref().map(|v| BASE64_STANDARD.encode(v));
    <Option<String>>::serialize(&base64, s)
}

pub fn from_option_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let base64 = <Option<String>>::deserialize(d)?;
    match base64 {
        Some(v) => BASE64_STANDARD
            .decode(v.as_bytes())
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

pub fn from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    use serde::de;
    <&str>::deserialize(deserializer).and_then(|s| {
        BASE64_STANDARD
            .decode(s)
            .map_err(|e| de::Error::custom(format!("invalid base64 string: {s}, {e}")))
    })
}

pub fn to_base64<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = BASE64_STANDARD.encode(v);
    String::serialize(&base64, s)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn bool_to_integer<S: Serializer>(v: &bool, s: S) -> Result<S::Ok, S::Error> {
    let i = u8::from(*v);
    u8::serialize(&i, s)
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetAddressesResponse {
    pub Code: ErrorCode,
    pub Addresses: Vec<AddressResponse>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AddressResponse {
    pub ID: String,
    pub DomainID: String,
    pub Email: String,
    pub DisplayName: String,
    pub Keys: Vec<AddressKey>,
}

#[derive(Derivative, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[derivative(Debug)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AddressKey {
    pub ID: String,
    pub Fingerprint: String,
    pub Fingerprints: Vec<String>,
    pub PublicKey: String,
    #[derivative(Debug = "ignore")]
    pub PrivateKey: String,
    #[derivative(Debug = "ignore")]
    pub Token: String,
    pub Signature: String,
    #[serde(
        deserialize_with = "deserialize_bool_from_anything",
        serialize_with = "bool_to_integer"
    )]
    pub Primary: bool,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct KeySalts {
    pub KeySalts: Vec<Salt>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Salt {
    pub ID: String,
    #[serde(
        deserialize_with = "from_option_base64",
        serialize_with = "to_option_base64"
    )]
    pub KeySalt: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RegisteredKey {
    pub AttestationFormat: String,
    pub CredentialID: Vec<u32>,
    pub Name: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FIDO2Info {
    pub AuthenticationOptions: Option<Vec<String>>,
    pub RegisteredKeys: Vec<RegisteredKey>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct TwoFAInfo {
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub Enabled: bool,
    pub FIDO2: FIDO2Info,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub TOTP: bool,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AuthInfo {
    pub Code: ErrorCode,
    pub Version: u8,
    pub Username: String,
    pub Modulus: String,
    pub ServerEphemeral: String,
    pub Salt: String,
    pub SRPSession: String,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub(crate) enum PasswordMode {
    None = 0,
    Single = 1,
    Dual = 2,
}

#[derive(Derivative, Deserialize)]
#[derivative(Debug)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Auth {
    pub Code: ErrorCode,
    pub LocalID: u32,
    pub TokenType: String,
    #[derivative(Debug = "ignore")]
    pub AccessToken: String,
    #[derivative(Debug = "ignore")]
    pub RefreshToken: String,
    pub Scopes: Vec<String>,
    pub UID: String,
    pub UserID: String,
    pub EventID: String,
    pub PasswordMode: PasswordMode,
    pub ServerProof: String,
    pub Scope: String,
    pub Uid: String,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub TwoFactor: bool,
    #[serde(rename = "2FA")]
    pub TwoFA: TwoFAInfo,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub TemporaryPassword: bool,
}

#[derive(Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AuthRequest<'a> {
    pub Username: &'a str,
    pub ClientEphemeral: &'a str,
    pub ClientProof: &'a str,
    pub SRPSession: &'a str,
}

#[derive(Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Auth2FARequest<'a> {
    pub TwoFactorCode: &'a str,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Auth2FA {
    pub Scope: String,
    pub Scopes: Vec<String>,
}

#[derive(Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AuthInfoRequest<'a> {
    pub Username: &'a str,
    pub Intent: &'a str,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct UserResponse {
    pub User: Option<User>,
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Zeroize, Debug, Clone, Copy,
)]
#[repr(u8)]
pub(crate) enum DelinquentState {
    Paid = 0,
    Available = 1,
    Overdue = 2,
    Delinquent = 3,
    NotReceived = 4,
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Zeroize, Debug, Clone, Copy,
)]
#[repr(u8)]
pub(crate) enum UserType {
    Proton = 1,  // internal
    Managed = 2, // sub-user
    External = 3,
    Credentialless = 4,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ProductUsedSpace {
    pub Calendar: u64,
    pub Contact: u64,
    pub Drive: u64,
    pub Mail: u64,
    pub Pass: u64,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct User {
    pub ID: String,
    pub Type: UserType,
    pub Name: String,
    pub UsedSpace: u64,
    pub ProductUsedSpace: ProductUsedSpace,
    pub MaxSpace: u64,
    #[serde(
        deserialize_with = "deserialize_bool_from_anything",
        serialize_with = "bool_to_integer"
    )]
    pub Private: bool,
    pub Subscribed: u32,
    pub Services: u32,
    pub Delinquent: DelinquentState,
    pub Email: String,
    pub DisplayName: String,
    pub Keys: Vec<LockedKey>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct LockedKey {
    pub ID: String,
    pub Version: u32,
    pub PrivateKey: String,
    pub Token: Option<String>,
    pub Signature: Option<String>,
    pub Activation: Option<String>,
    #[serde(
        deserialize_with = "deserialize_bool_from_anything",
        serialize_with = "bool_to_integer"
    )]
    pub Primary: bool,
    #[serde(
        deserialize_with = "deserialize_bool_from_anything",
        serialize_with = "bool_to_integer"
    )]
    pub Active: bool,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub(crate) struct PrivateKey {
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub(crate) struct PublicKey {
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub(crate) struct UnlockedUserKey {
    pub id: String,
    pub public: PublicKey,
    pub private: PrivateKey,
}

#[derive(Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RefreshSessionRequest {
    pub RefreshToken: String,
    pub ResponseType: &'static str,
    pub GrantType: &'static str,
}

impl RefreshSessionRequest {
    pub fn new(refresh_token: String) -> Self {
        Self {
            RefreshToken: refresh_token,
            ResponseType: "token",
            GrantType: "refresh_token",
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RefreshSessionResponse {
    pub Code: ErrorCode,
    pub Error: Option<String>,
    pub AccessToken: String,
    pub ExpiresIn: u64,
    pub TokenType: String,
    pub Scopes: Vec<String>,
    pub UID: String,
    pub RefreshToken: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct NodeBlock {
    pub Index: u64,
    pub Hash: String,
    pub Token: Option<String>,
    pub URL: Option<String>,
    pub BareURL: Option<String>,
    pub EncSignature: Option<String>,
    pub SignatureEmail: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RevisionResponse {
    pub Blocks: Vec<NodeBlock>,
    pub ID: String,
    pub ManifestSignature: Option<String>,
    pub Size: u64,
    pub State: RevisionState,
    pub XAttr: Option<String>,
    pub ClientUID: Option<String>,
    pub CreateTime: u64,
    pub SignatureEmail: String,
    pub SignatureAddress: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetRevisionResponse {
    pub Code: ErrorCode,
    pub Revision: RevisionResponse,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CheckAvailableHashesRequest {
    pub Hashes: Vec<String>,
    pub ClientUID: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CheckAvailableHashesResponse {
    pub Code: ErrorCode,
    pub AvailableHashes: Vec<String>,
    pub PendingHashes: Vec<PendingHash>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct PendingHash {
    pub Hash: String,
    pub RevisionID: String,
    pub LinkID: String,
    pub ClientUID: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DraftRequestResult {
    pub(crate) node_uid: String,
    pub(crate) node_revision_uid: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct LinkSharingDetails {
    pub ShareID: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FolderProperties {
    pub NodeHashKey: String,
    pub XAttr: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RevisionHeader {
    pub RevisionID: String,
    pub CreateTime: u64,
    pub EncryptedSize: u64,
    pub ManifestSignature: String,
    pub XAttr: Option<String>,
    pub SignatureEmail: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Thumbnail {
    pub ThumbnailID: String,
    pub Type: ThumbnailType,
    pub Size: u32,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u8)]
pub(crate) enum RevisionState {
    Draft = 0,
    Active = 1,
    Unknown = 2,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FileProperties {
    pub TotalEncryptedSize: u64,
    #[serde(deserialize_with = "from_base64")]
    pub ContentKeyPacket: Vec<u8>,
    pub MediaType: Option<String>,
    pub ActiveRevision: RevisionHeader,
    pub ContentKeyPacketSignature: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AlbumProperties {
    pub NodeHashKey: String,
    pub XAttr: Option<String>,
}

#[derive(Derivative, Deserialize)]
#[derivative(Debug)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Link {
    pub LinkID: String,
    pub Type: LinkType,
    pub ParentLinkID: Option<String>,
    pub State: LinkState,
    pub CreateTime: u64,
    pub ModifyTime: u64,
    pub TrashTime: Option<u64>,
    pub Name: String,
    pub NameHash: Option<String>,
    #[derivative(Debug = "ignore")]
    pub NodeKey: String,
    pub NodePassphrase: String,
    pub NodePassphraseSignature: String,
    pub SignatureEmail: Option<String>,
    pub NameSignatureEmail: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct LinkResponse {
    pub Link: Link,
    pub Folder: Option<FolderProperties>,
    pub File: Option<FileProperties>,
    pub Album: Option<AlbumProperties>,
    pub Sharing: Option<LinkSharingDetails>,
    pub Membership: Option<LinkMembership>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct LinkMembership {
    pub ShareID: String,
    pub MembershipID: String,
    pub Permissions: u32,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct LinksResponse {
    pub Links: Vec<LinkResponse>,
    pub Code: ErrorCode,
}

#[allow(non_snake_case, dead_code)]
struct BaseNode {
    pub Hash: Option<String>, // root node doesn't have any hash
    pub EncryptedName: String,
    pub Uid: String,
    pub ParentUid: Option<String>,
    pub Type: NodeType,
    pub MediaType: Option<String>,
    pub CreationTime: u64,
    pub TrashTime: u64,
    pub TotalStorageSize: Option<u64>,
    pub ShareId: Option<String>,
    pub IsShared: bool,
    pub DirectMemberRole: MemberRole,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DeleteDraftResponse {
    pub Code: ErrorCode,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DeleteDraftRequestPayload {
    pub LinkIDs: Vec<String>,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct LinksRequestPayload {
    pub LinkIDs: Vec<String>,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DeleteLinksRequestPayload {
    pub LinkIDs: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DeleteLinksResponse {
    pub Code: Option<ErrorCode>,
    pub Responses: Option<Vec<DeleteLinkResponse>>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DeleteLinkResponse {
    pub LinkID: String,
    pub Response: DeleteLinkResponseResponse,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DeleteLinkResponseResponse {
    pub Code: Option<ErrorCode>,
    pub Error: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedNode {
    pub Hash: Option<String>, // root node doesn't have any hash
    pub EncryptedName: String,
    pub Uid: String,
    pub ParentUid: Option<String>,
    pub Type: NodeType,
    pub MediaType: Option<String>,
    pub CreationTime: u64,
    pub TrashTime: u64,
    pub TotalStorageSize: Option<u64>,
    pub ShareId: Option<String>,
    pub IsShared: bool,
    pub DirectMemberRole: MemberRole,
    pub(crate) EncryptedCrypto: EncryptedNodeCrypto,
}

#[derive(Debug, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedNodeCrypto {
    pub SignatureEmail: Option<String>,
    pub NameSignatureEmail: Option<String>,
    pub ArmoredKey: String,
    pub ArmoredNodePassphrase: String,
    pub ArmoredNodePassphraseSignature: String,
    pub File: Option<EncryptedNodeFile>,
    pub ActiveRevision: Option<EncryptedRevision>,
    pub Folder: Option<EncryptedNodeFolder>,
    pub Album: Option<EncryptedNodeAlbum>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedNodePhoto {
    pub NodeHashKey: String,
    pub XAttr: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedNodeFile {
    #[serde(
        deserialize_with = "from_base64",
        serialize_with = "to_base64",
        rename = "Base64ContentKeyPacket"
    )]
    pub ContentKeyPacket: Vec<u8>,
    pub ArmoredContentKeyPacketSignature: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedNodeFolder {
    pub ArmoredExtendedAttributes: Option<String>,
    pub ArmoredHashKey: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedNodeAlbum {
    pub XAttr: Option<String>,
    pub NodeHashKey: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedRevision {
    pub UID: String,
    pub State: RevisionState,
    pub CreationTime: u64,
    pub storageSize: u64,
    pub SignatureEmail: Option<String>,
    pub ArmoredExtendedAttributes: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RenameLinkParameters {
    pub Name: String,
    pub Hash: String,
    pub MediaType: Option<String>,
    pub NameSignatureEmail: String,
    pub OriginalNameHash: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct RenameLinkResponse {
    pub Code: ErrorCode,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct DecryptedNode<PGPProv: proton_crypto::crypto::PGPProviderSync> {
    pub encrypted: EncryptedNode,
    pub name: String,
    pub author_name: String,
    pub(crate) keys: UnlockedUserKey,
    pub(crate) name_verification_key: PublicKey,
    pub(crate) content_session_key: Option<PGPProv::SessionKey>,
    pub(crate) hash_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct NodeChildrenResponse {
    pub LinkIDs: Vec<String>,
    pub More: bool,
    pub AnchorID: Option<String>,
    pub Code: ErrorCode,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateFolderRequest {
    pub NodeHashKey: String,
    pub XAttr: Option<String>,
    pub Name: String,
    pub Hash: String,
    pub ParentLinkID: String,
    pub NodePassphrase: String,
    pub NodePassphraseSignature: String,
    pub SignatureEmail: String,
    pub NodeKey: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateFolderResponse {
    pub Folder: CreateFolderIDResponse,
    pub Code: ErrorCode,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateDraftRequest {
    pub MIMEType: String,
    #[serde(serialize_with = "to_base64")]
    pub ContentKeyPacket: Vec<u8>,
    pub ContentKeyPacketSignature: Option<String>,
    pub IntendedUploadSize: Option<u64>,
    pub Name: String,
    pub Hash: String,
    pub ParentLinkID: String,
    pub NodePassphrase: String,
    pub NodePassphraseSignature: String,
    pub SignatureAddress: String,
    pub NodeKey: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateDraftResponse {
    pub Code: ErrorCode,
    pub File: Option<FileDraftResponse>,
    pub Details: Option<DraftResponseErrorDetails>,
    pub Error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FileDraftResponse {
    pub ID: String,
    pub RevisionID: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DraftResponseErrorDetails {
    pub ConflictLinkID: String,
    pub ConflictRevisionID: Option<String>,
    pub ConflictDraftRevisionID: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateFolderIDResponse {
    pub ID: String,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u8)]
pub(crate) enum ThumbnailType {
    Type1 = 1,
    Type2 = 2,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub(crate) enum LinkType {
    None = 0,
    Folder = 1,
    File = 2,
    Album = 3,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub(crate) enum LinkState {
    Draft = 0,
    Active = 1,
    Trashed = 2,
    Deleted = 3,
    Restoring = 4,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u8)]
pub(crate) enum NodeType {
    None = 0,
    File = 1,
    Folder = 2,
    Album = 3,
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u8)]
pub(crate) enum MemberRole {
    Viewer = 0,
    Editor = 1,
    Admin = 2,
    Inherited = 3,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FileExtendedAttributesSchema {
    pub Common: Option<FileExtendedAttributesSchemaCommon>,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FileExtendedAttributesSchemaCommon {
    pub ModificationTime: String,
    pub Size: usize,
    pub BlockSizes: Vec<usize>,
    pub Digests: FileExtendedAttributesSchemaDigest,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct FileExtendedAttributesSchemaDigest {
    pub SHA1: String,
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone, Zeroize,
)]
#[repr(u8)]
pub(crate) enum ShareType {
    None = 0,
    Main = 1,
    Standard = 2,
    Device = 3,
    Photos = 4,
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone, Zeroize,
)]
#[repr(u8)]
pub(crate) enum ShareState {
    None = 0,
    Active = 1,
    Deleted = 2,
    Restored = 3,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ShareMembership {
    pub MemberID: Option<String>,
    pub ShareID: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct VolumeShareNodeIDs {
    pub ShareID: String,
    pub VolumeID: String,
    pub RootNodeId: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct Volume {
    pub ShareID: String,
    pub VolumeID: String,
    pub RootNodeId: String,
    pub CreatorEmail: String,
    pub AddressID: String,
}

#[derive(Debug)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct DecryptedRootShare {
    pub ShareID: String,
    pub VolumeID: String,
    pub RootNodeId: String,
    pub AddressID: String,
    pub CreationTime: Option<u64>,
    pub Type: ShareType,
    pub Author: Result<String, UnverifiedAuthorError>,
}

#[derive(Debug)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct UnverifiedAuthorError {
    ClaimedAuthor: Option<String>,
    Error: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedShareCrypto {
    pub ArmoredKey: String,
    pub ArmoredPassphrase: String,
    pub ArmoredPassphraseSignature: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct EncryptedRootShare {
    pub ShareID: String,
    pub VolumeID: String,
    pub RootNodeId: String,
    pub AddressID: String,
    pub CreationTime: Option<u64>,
    pub Type: ShareType,
    pub CreatorEmail: String,
    pub EncryptedCrypto: EncryptedShareCrypto,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetMyFilesVolumeResponse {
    pub VolumeID: String,
    pub UsedSpace: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetMyFilesShareResponse {
    pub ShareID: String,
    pub CreatorEmail: String,
    pub Key: String,
    pub Passphrase: String,
    pub PassphraseSignature: String,
    pub AddressID: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetMyFilesLinkResponse {
    pub Link: GetMyFilesLinkLinkResponse,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetMyFilesLinkLinkResponse {
    pub LinkID: String,
    pub Type: u8,
    pub ParentLinkID: Option<String>,
    pub State: ShareState,
    pub CreateTime: u64,
    pub ModifyTime: u64,
    pub TrashTime: Option<u64>,
    pub Name: String,
    pub NameHash: Option<String>,
    pub NodeKey: String,
    pub NodePassphrase: String,
    pub NodePassphraseSignature: String,
    pub SignatureEmail: Option<String>,
    pub NameSignatureEmail: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct GetMyFilesResponse {
    pub Volume: GetMyFilesVolumeResponse,
    pub Share: GetMyFilesShareResponse,
    pub Link: GetMyFilesLinkResponse,
    pub Code: ErrorCode,
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone, Zeroize,
)]
#[repr(u8)]
pub(crate) enum ShareFlag {
    None = 0,
    Primary = 1,
}

#[derive(Debug, Deserialize, Serialize, Clone, Zeroize, ZeroizeOnDrop)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ShareListItem {
    pub ShareID: String,
    pub Type: ShareType,
    pub State: ShareState,
    pub LinkID: String,
    pub VolumeID: String,
    pub Creator: Option<String>,
    pub Flags: ShareFlag,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub Locked: bool,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub VolumeSoftDeleted: bool,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ShareListResponse {
    pub Code: ErrorCode,
    pub Shares: Vec<ShareListItem>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct PhotoLinksResponse {
    pub Photos: Vec<PhotoLink>,
    pub Code: ErrorCode,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct PhotoLink {
    pub LinkID: String,
    pub CaptureTime: u64,
    pub Hash: String,
    pub ContentHash: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AlbumLinksResponse {
    pub Photos: Vec<AlbumLink>,
    pub Code: ErrorCode,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub More: bool,
    pub AnchorID: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AlbumLink {
    pub LinkID: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateAlbumRequest {
    pub Locked: bool,
    pub Link: CreateAlbumLink,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateAlbumLink {
    pub Name: String,
    pub Hash: String,
    pub NodePassphrase: String,
    pub NodePassphraseSignature: String,
    pub SignatureEmail: String,
    pub NodeKey: String,
    pub NodeHashKey: String,
    pub XAttr: Option<String>
}
    
#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreateAlbumResponse {
    pub Code: ErrorCode,
    pub Album: Option<CreatedAlbum>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CreatedAlbum {
    pub Link: AlbumLink
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AlbumLiink {
    pub LinkID: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AddPhotoToAlbumRequest {
    pub AlbumData: Vec<AddPhotoToAlbumData>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AddPhotoToAlbumData {
    pub LinkID: String,
    pub Hash: String,
    pub Name: String,
    pub NameSignatureEmail: String,
    pub NodePassphrase: String,
    pub ContentHash: String,
    pub NodePassphraseSignature: Option<String>,
    pub SignatureEmail: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct AddPhotoToAlbumResponse {
    pub Code: ErrorCode,
}

#[derive(Debug, Deserialize, Serialize, Clone, Zeroize, ZeroizeOnDrop)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ShareResponse {
    pub ShareID: String,
    pub Type: ShareType,
    pub State: ShareState,
    pub LinkID: String,
    pub VolumeID: String,
    pub Creator: Option<String>,
    pub Flags: ShareFlag,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub Locked: bool,
    #[serde(deserialize_with = "deserialize_bool_from_anything")]
    pub VolumeSoftDeleted: bool,
    pub Key: String,
    pub Passphrase: String,
    pub PassphraseSignature: String,
    pub AddressID: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct BlockUploadRequest {
    pub AddressID: String,
    pub VolumeID: String,
    pub LinkID: String,
    pub RevisionID: String,
    pub BlockList: Vec<BlockUpload>,
    pub ThumbnailList: Vec<ThumbnailUpload>,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ThumbnailUpload {
    pub Type: ThumbnailType,
    pub Size: usize,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    pub Hash: Vec<u8>,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct BlockUpload {
    pub Index: usize,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    pub Hash: Vec<u8>,
    pub EncSignature: String,
    pub Size: usize,
    pub Verifier: BlockUploadVerifier,
}

#[derive(Debug, Serialize, Clone)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct BlockUploadVerifier {
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    pub Token: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct BlockUploadResponse {
    pub Code: ErrorCode,
    pub UploadLinks: Vec<BlockUploadLink>,
    pub ThumbnailLinks: Vec<ThumbnailUploadLink>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct ThumbnailUploadLink {
    pub BareURL: String,
    pub Token: String,
    pub URL: String,
    ThumbnailType: ThumbnailType,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct BlockUploadLink {
    pub BareURL: String,
    pub Token: String,
    pub URL: String,
    pub Index: usize,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct BlockVerificationData {
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    pub VerificationCode: Vec<u8>,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    pub ContentKeyPacket: Vec<u8>,
    pub Code: ErrorCode,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CommitDraftRequest {
    pub ManifestSignature: String,
    pub SignatureAddress: String,
    pub XAttr: Option<String>,
    pub Photo: Option<CommitDraftPhoto>,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CommitDraftPhoto {
    pub CaptureTime: i64,
    pub ContentHash: String,
    pub MainPhotoLinkID: Option<String>,
    pub Tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CommitDraftResponse {
    pub Code: ErrorCode,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case, dead_code)]
pub(crate) struct CommitBlock {
    pub Index: usize,
    pub Token: String,
    pub Size: usize,
}
