//! Length-prefixed CBOR framing for QUIC streams.
//!
//! All QUIC-based protocols in mlsh use a 4-byte big-endian length prefix
//! followed by a CBOR payload. This module centralises that logic.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_MSG_SIZE: usize = 1_048_576; // 1 MiB

/// Write a length-prefixed CBOR message.
pub async fn write_msg<T: serde::Serialize>(
    send: &mut (impl AsyncWrite + Unpin),
    msg: &T,
) -> anyhow::Result<()> {
    let mut cbor = Vec::new();
    ciborium::into_writer(msg, &mut cbor)
        .map_err(|e| anyhow::anyhow!("CBOR encode failed: {}", e))?;
    let len = (cbor.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&cbor).await?;
    Ok(())
}

/// Read a length-prefixed CBOR message, returning `None` on clean EOF.
pub async fn read_msg_opt<T: serde::de::DeserializeOwned>(
    recv: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(Some(ciborium::from_reader(&buf[..]).map_err(|e| {
        anyhow::anyhow!("CBOR decode failed: {}", e)
    })?))
}

/// Read a length-prefixed CBOR message. Returns an error on EOF.
pub async fn read_msg<T: serde::de::DeserializeOwned>(
    recv: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<T> {
    read_msg_opt(recv)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Unexpected EOF"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame_cbor<T: serde::Serialize>(msg: &T) -> Vec<u8> {
        let mut cbor = Vec::new();
        ciborium::into_writer(msg, &mut cbor).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        buf.extend_from_slice(&cbor);
        buf
    }

    #[tokio::test]
    async fn roundtrip_via_duplex() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);

        let msg = serde_json::json!({"hello": "world"});
        write_msg(&mut writer, &msg).await.unwrap();
        drop(writer);

        let result: serde_json::Value = read_msg(&mut reader).await.unwrap();
        assert_eq!(result, msg);
    }

    #[tokio::test]
    async fn read_msg_opt_returns_none_on_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: Option<serde_json::Value> = read_msg_opt(&mut cursor).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn read_msg_errors_on_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: anyhow::Result<serde_json::Value> = read_msg(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_message() {
        let len = (MAX_MSG_SIZE as u32 + 1).to_be_bytes();
        let mut cursor = Cursor::new(len.to_vec());
        let result: anyhow::Result<serde_json::Value> = read_msg(&mut cursor).await;
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn multiple_messages_sequential() {
        let mut buf = frame_cbor(&"first");
        buf.extend_from_slice(&frame_cbor(&"second"));
        let mut cursor = Cursor::new(buf);

        let first: String = read_msg(&mut cursor).await.unwrap();
        let second: String = read_msg(&mut cursor).await.unwrap();
        assert_eq!(first, "first");
        assert_eq!(second, "second");
    }

    #[tokio::test]
    async fn read_msg_opt_returns_none_after_last_message() {
        let buf = frame_cbor(&42i32);
        let mut cursor = Cursor::new(buf);

        let msg: Option<i32> = read_msg_opt(&mut cursor).await.unwrap();
        assert_eq!(msg, Some(42));

        let eof: Option<i32> = read_msg_opt(&mut cursor).await.unwrap();
        assert!(eof.is_none());
    }
}
