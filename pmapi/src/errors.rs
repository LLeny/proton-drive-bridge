use thiserror::Error;

#[derive(Error, Debug)]
pub enum APIError {
    #[error("the url `{0}` is not valid")]
    UrlError(String),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("reqwest error, couldn't deserialize JSON: {0}")]
    DeserializeJSON(String),
    #[error("SRP error: {0}")]
    SRP(#[from] proton_srp::SRPError),
    #[error("PGP error: {0}")]
    PGP(String),
    #[error("Salt error: {0}")]
    Salt(String),
    #[error("Share error: {0}")]
    Share(String),
    #[error("Node error: {0}")]
    Node(String),
    #[error("Download error: {0}")]
    Download(String),
    #[error("Upload error: {0}")]
    Upload(String),
    #[error("Account error: {0}")]
    Account(String),    
    #[error("Image error: {0}")]
    Image(String),
    #[error("unknown API error: {0}")]
    Unknown(String),
}

#[derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub(crate) enum ErrorCode {
    NO_ROUTE_FOR = 0,
    PATH_NOT_FOUND = 404,
    OK = 1000,
    OK_MANY = 1001,
    OK_ASYNC = 1002,
    INVALID_INPUT = 2001,
    UNKNOWN_2002 = 2002,
    NOT_ENOUGH_PERMISSIONS = 2011,
    NOT_ENOUGH_PERMISSIONS_TO_GRANT_PERMISSIONS = 2026,
    ALREADY_EXISTS = 2500,
    NOT_EXISTS = 2501,
    INSUFFICIENT_QUOTA = 200_001,	
    INSUFFICIENT_SPACE = 200_002,
    MAX_FILE_SIZE_FOR_FREE_USER = 200_003,
    MAX_PUBLIC_EDIT_MODE_FOR_FREE_USER = 200_004,
    INSUFFICIENT_VOLUME_QUOTA= 200_100,
    INSUFFICIENT_DEVICE_QUOTA= 200_101,
    ALREADY_MEMBER_OF_SHARE_IN_VOLUME_WITH_ANOTHER_ADDRESS = 200_201,
    TOO_MANY_CHILDREN = 200_300,
    NESTING_TOO_DEEP = 200_301,
    INSUFFICIENT_INVITATION_QUOTA = 200_600,	
    INSUFFICIENT_SHARE_QUOTA = 200_601,
    INSUFFICIENT_SHARE_JOINED_QUOTA = 200_602,
    INSUFFICIENT_BOOKMARKS_QUOTA = 200_800,
}

impl ErrorCode {
    pub(crate) fn is_error(&self) -> bool {
        !self.is_ok()
    }

    pub(crate) fn is_ok(&self) -> bool {
        matches!(self, ErrorCode::OK | ErrorCode::OK_MANY | ErrorCode::OK_ASYNC)
    }
}

pub type Result<T> = std::result::Result<T, crate::errors::APIError>;
