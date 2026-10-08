//! Length-prefixed JSON messages: a 4-byte big-endian length, then that many
//! bytes of JSON. Buffers are zeroed after use because control messages
//! carry passphrases and secret values.

use std::io;

use kv_core::proto::MAX_FRAME_LEN;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = Zeroizing::new(serde_json::to_vec(message).map_err(invalid_data)?);
    if body.len() > MAX_FRAME_LEN {
        return Err(invalid_data("message is larger than the frame limit"));
    }
    let len = u32::try_from(body.len()).expect("frame limit fits in u32");
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}

/// Returns `Ok(None)` when the peer closed the connection between messages.
/// Oversized or malformed frames are `InvalidData` errors.
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(invalid_data("frame is larger than the frame limit"));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(invalid_data)
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_core::proto::AgentRequest;

    #[tokio::test]
    async fn round_trips_messages_in_order() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &AgentRequest::Status).await.unwrap();
            write_frame(&mut a, &AgentRequest::ListHandles)
                .await
                .unwrap();
        });
        let first: Option<AgentRequest> = read_frame(&mut b).await.unwrap();
        let second: Option<AgentRequest> = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(first, Some(AgentRequest::Status));
        assert_eq!(second, Some(AgentRequest::ListHandles));
        let end: Option<AgentRequest> = read_frame(&mut b).await.unwrap();
        assert_eq!(end, None);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let err = read_frame::<_, AgentRequest>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&3u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{x}").await.unwrap();
        let err = read_frame::<_, AgentRequest>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error_not_a_clean_close() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{\"ty").await.unwrap();
        drop(a);
        let err = read_frame::<_, AgentRequest>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
