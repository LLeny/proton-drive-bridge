use crate::errors::{APIError, Result};

pub(crate) fn make_node_uid(volume_id: &str, node_id: &str) -> String {
    make_uid([volume_id, node_id])
}

pub(crate) fn make_node_revision_uid(volume_id: &str, node_id: &str, revision_id: &str) -> String {
    make_uid([volume_id, node_id, revision_id])
}

pub(crate) fn split_node_revision_uid(node_revision_uid: &str) -> Result<(String, String, String)> {
    let ids = split_uid(node_revision_uid, 3)?;
    Ok((ids[0].clone(), ids[1].clone(), ids[2].clone()))
}

pub(crate) fn split_node_uid(node_uid: &str) -> Result<(String, String)> {
    let ids = split_uid(node_uid, 2)?;
    Ok((ids[0].clone(), ids[1].clone()))
}

fn make_uid<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let slice: Vec<&str> = parts.into_iter().collect();
    slice.join("~")
}

fn split_uid(uid: &str, expected_parts: usize) -> Result<Vec<String>> {
    let parts: Vec<&str> = uid.split('~').collect();
    if parts.len() == expected_parts {
        Ok(parts
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>())
    } else {
        Err(APIError::Unknown(format!(
            "'{uid}' is not a valid {expected_parts} UID"
        )))
    }
}
