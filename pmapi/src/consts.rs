pub(crate) const APP_VERSION: &str = "windows-drive@1.10.1";
pub(crate) const URL_API_HOST: &str = "https://account.proton.me/api/";
pub(crate) const AUTH_INFO_ENDPOINT: &str = "core/v4/auth/info";
pub(crate) const AUTH_ENDPOINT: &str = "core/v4/auth";
pub(crate) const USERS_ENDPOINT: &str = "core/v4/users";
pub(crate) const SALTS_ENDPOINT: &str = "core/v4/keys/salts";
pub(crate) const ADDRESSES_ENDPOINT: &str = "core/v4/addresses";
pub(crate) const AUTH_2FA_ENDPOINT: &str = "core/v4/auth/2fa";
pub(crate) const DRIVE_LINKS_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/links";
pub(crate) const DRIVE_SHARES_MYFILES_ENDPOINT: &str = "drive/v2/shares/my-files";
pub(crate) const DRIVE_NODE_CHILDREN: &str = "drive/v2/volumes/{volume_id}/folders/{node_id}/children";
pub(crate) const DRIVE_NODE_REVISION: &str = "drive/v2/volumes/{volume_id}/files/{node_id}/revisions/{revision_id}?PageSize={BLOCKS_PAGE_SIZE}&FromBlockIndex={from_block_index}";
pub(crate) const DRIVE_TRASH_LINKS_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/trash_multiple";
pub(crate) const DRIVE_DELETE_LINKS_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/trash/delete_multiple";
pub(crate) const DRIVE_RENAME_LINK_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/links/{node_id}/rename";
pub(crate) const DRIVE_CHECKHASH_LINK_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/links/{node_id}/checkAvailableHashes";
pub(crate) const DRIVE_CREATE_FOLDER_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/folders";
pub(crate) const DRIVE_CREATE_DRAFT_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/files";
pub(crate) const DRIVE_DELETE_DRAFT_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/delete_multiple";
pub(crate) const DRIVE_BLOCK_UPLOAD_REQUEST_ENDPOINT: &str = "drive/blocks";
pub(crate) const DRIVE_BLOCK_VERIFICATION_DATA_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/links/{node_id}/revisions/{revision_id}/verification";
pub(crate) const DRIVE_COMMIT_REVISION_ENDPOINT: &str = "drive/v2/volumes/{volume_id}/files/{node_id}/revisions/{revision_id}";

pub(crate) const PASSPHRASE_LEN: usize = 32;
pub(crate) const HASHKEY_LEN: usize = 32;
pub(crate) const BLOCKS_PAGE_SIZE: u16 = 20;
pub(crate) const FILE_CHUNK_SIZE: usize = 4 * 1024 * 1024;

pub(crate) const NODEKEY_USER: &str = "Drive key";
pub(crate) const NODEKEY_EMAIL: &str = "no-reply@proton.me";

pub(crate) const _GENERAL_RETRY_DELAY_SECONDS: u16 = 1;