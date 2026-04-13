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

    #[tokio::test]
    async fn truncated_length_prefix() {
        // Only 2 bytes instead of 4
        let mut cursor = Cursor::new(vec![0x00, 0x01]);
        let result: anyhow::Result<Option<String>> = read_msg_opt(&mut cursor).await;
        // Partial length header → EOF during read_exact → None
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_payload() {
        // Header says 100 bytes but only 5 bytes of payload follow
        let mut buf = (100u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&[0xA1, 0x61, 0x61, 0x01, 0x02]);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<serde_json::Value> = read_msg(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn zero_length_payload() {
        // Header says 0 bytes → empty CBOR input should fail to decode
        let buf = (0u32).to_be_bytes().to_vec();
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<String> = read_msg(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn invalid_cbor_payload() {
        // Valid length header but garbage CBOR
        let garbage = vec![0xFF, 0xFE, 0xFD];
        let mut buf = (garbage.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&garbage);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<String> = read_msg(&mut cursor).await;
        assert!(
            result.is_err(),
            "garbage CBOR payload should cause decode error"
        );
    }

    #[tokio::test]
    async fn roundtrip_protocol_types() {
        use crate::messages::{ServerMessage, StreamMessage};
        use crate::types::Candidate;

        let (mut writer, mut reader) = tokio::io::duplex(4096);

        // Write a StreamMessage
        let client_msg = StreamMessage::ReportCandidates {
            candidates: vec![Candidate {
                kind: "host".into(),
                addr: "10.0.0.1:4433".into(),
                priority: 100,
            }],
        };
        write_msg(&mut writer, &client_msg).await.unwrap();

        // Write a ServerMessage
        let server_msg = ServerMessage::NodeAuthOk {
            cluster_id: "c1".into(),
            overlay_ip: "100.64.0.1".into(),
            overlay_subnet: "100.64.0.0/10".into(),
            peers: vec![],
        };
        write_msg(&mut writer, &server_msg).await.unwrap();
        drop(writer);

        // Read them back in order
        let decoded_client: StreamMessage = read_msg(&mut reader).await.unwrap();
        match decoded_client {
            StreamMessage::ReportCandidates { candidates } => {
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].addr, "10.0.0.1:4433");
            }
            other => panic!("expected ReportCandidates, got {:?}", other),
        }

        let decoded_server: ServerMessage = read_msg(&mut reader).await.unwrap();
        match decoded_server {
            ServerMessage::NodeAuthOk { overlay_ip, .. } => {
                assert_eq!(overlay_ip, "100.64.0.1");
            }
            other => panic!("expected NodeAuthOk, got {:?}", other),
        }

        // Stream should be exhausted
        let eof: Option<serde_json::Value> = read_msg_opt(&mut reader).await.unwrap();
        assert!(eof.is_none());
    }

    // ===================================================================
    // CBOR attack vector tests (framing layer)
    // ===================================================================

    /// Depth bomb through framing: valid length prefix wrapping deeply nested CBOR.
    #[tokio::test]
    async fn framing_depth_bomb() {
        use crate::messages::StreamMessage;
        let depth = 10_000usize;
        let mut cbor = vec![0x81u8; depth];
        cbor.push(0x60); // empty text to close
        let mut buf = (cbor.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&cbor);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<StreamMessage> = read_msg(&mut cursor).await;
        // Must not panic/stack overflow. Error is expected.
        assert!(result.is_err());
    }

    /// Huge allocation through framing: CBOR claims massive array inside valid frame.
    #[tokio::test]
    async fn framing_huge_allocation_in_payload() {
        use crate::messages::StreamMessage;
        // CBOR: array(4 billion) — but the frame is only 9 bytes of CBOR.
        // ciborium reads from a fixed-size buffer, so it will hit EOF before allocating.
        let cbor: Vec<u8> = vec![0x9B, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut buf = (cbor.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&cbor);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<StreamMessage> = read_msg(&mut cursor).await;
        assert!(result.is_err());
    }

    /// Type confusion through framing: valid frame but CBOR contains a bare integer.
    #[tokio::test]
    async fn framing_type_confusion() {
        use crate::messages::StreamMessage;
        let mut cbor = Vec::new();
        ciborium::into_writer(&42u64, &mut cbor).unwrap();
        let mut buf = (cbor.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&cbor);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<StreamMessage> = read_msg(&mut cursor).await;
        assert!(
            result.is_err(),
            "bare integer must not decode as StreamMessage"
        );
    }

    /// Unknown variant through framing: valid CBOR map with fake tag.
    #[tokio::test]
    async fn framing_unknown_variant() {
        use crate::messages::StreamMessage;
        let fake = ciborium::Value::Map(vec![(
            ciborium::Value::Text("hack_me".into()),
            ciborium::Value::Map(vec![]),
        )]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&fake, &mut cbor).unwrap();
        let mut buf = (cbor.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&cbor);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<StreamMessage> = read_msg(&mut cursor).await;
        assert!(
            result.is_err(),
            "unknown variant through framing must be rejected"
        );
    }

    /// Multiple attack payloads in sequence: first bad, second valid.
    /// Verify the stream is not corrupted after a decode error.
    #[tokio::test]
    async fn bad_message_does_not_corrupt_stream() {
        use crate::messages::ServerMessage;
        // First message: garbage CBOR
        let garbage_cbor = vec![0xFF, 0xFE];
        let mut buf = (garbage_cbor.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&garbage_cbor);
        // Second message: valid ServerMessage::Pong
        buf.extend_from_slice(&frame_cbor(&ServerMessage::Pong));

        let mut cursor = Cursor::new(buf);

        // First read should fail
        let result1: anyhow::Result<ServerMessage> = read_msg(&mut cursor).await;
        assert!(result1.is_err());

        // Second read should succeed — the framing consumed exactly the first frame
        let result2: ServerMessage = read_msg(&mut cursor).await.unwrap();
        match result2 {
            ServerMessage::Pong => {}
            other => panic!("expected Pong after bad frame, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_exactly_at_max_size() {
        // Exactly MAX_MSG_SIZE should be accepted (not rejected)
        let len = (MAX_MSG_SIZE as u32).to_be_bytes();
        let mut buf = len.to_vec();
        // We won't provide the full payload — just verify the length check passes
        // and the error is about EOF (payload too short), not "too large".
        buf.extend_from_slice(&[0u8; 64]);
        let mut cursor = Cursor::new(buf);
        let result: anyhow::Result<serde_json::Value> = read_msg(&mut cursor).await;
        let err_msg = result.unwrap_err().to_string();
        assert!(
            !err_msg.contains("too large"),
            "MAX_MSG_SIZE exactly should not be rejected as too large"
        );
    }
}
